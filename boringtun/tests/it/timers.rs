//! Timer behaviour (whitepaper §6): handshake retransmission, rekeying,
//! passive and persistent keepalives, and session expiry.

use crate::harness::{
    assert_close, assert_fires_at, ipv4_packet, secs, Kind, Outcome as _, Peer::A, Peer::B, Sim,
    KEEPALIVE_TIMEOUT, MAX_JITTER, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT, SHOULD_NOT_USE_AFTER_TIME, TICK,
};
use boringtun::noise::errors::WireGuardError;

/// §6.4: an unanswered handshake initiation is retransmitted after
/// `REKEY_TIMEOUT + jitter`, where jitter is up to 333ms.
#[test]
fn unanswered_handshake_is_retransmitted_every_rekey_timeout() {
    let mut sim = Sim::new();
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(18));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 4, "one initiation plus three retries in 18s");
    for pair in inits.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= REKEY_TIMEOUT && gap <= REKEY_TIMEOUT + MAX_JITTER + 2 * TICK,
            "retransmission gap was {gap:?}"
        );
    }
}

/// §6.4: retries cease after `REKEY_ATTEMPT_TIME` and the tunnel reports
/// itself as expired.
#[test]
fn handshake_retries_cease_after_rekey_attempt_time() {
    let mut sim = Sim::new();
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(120));

    let inits = sim.sent_at(A, Kind::Init);
    assert!(
        inits.iter().all(|at| *at < REKEY_ATTEMPT_TIME),
        "no initiation may be sent after REKEY_ATTEMPT_TIME"
    );
    assert!(
        inits.len() >= 16,
        "expected steady retries for 90s, got {}",
        inits.len()
    );
    assert!(sim.tunn(A).is_expired());
    assert!(sim
        .errors(A)
        .iter()
        .any(|e| matches!(e, WireGuardError::ConnectionExpired)));
}

#[test]
fn expired_tunnel_recovers_on_explicit_handshake() {
    let mut sim = Sim::new();
    sim.cut_link();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(95));
    assert!(sim.tunn(A).is_expired());

    sim.heal_link();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);

    assert!(!sim.tunn(A).is_expired());
    sim.assert_connectivity();
}

#[test]
fn rekey_timeout_is_configurable() {
    let mut sim = Sim::new();
    sim.tunn_mut(A).set_rekey_timeout(secs(1));
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(5));

    let inits = sim.sent_at(A, Kind::Init);
    assert!(
        inits.len() >= 4,
        "expected retries every ~1s, got {}",
        inits.len()
    );
}

#[test]
fn rekey_attempt_time_is_configurable() {
    let mut sim = Sim::new();
    sim.tunn_mut(A).set_rekey_attempt_time(secs(10));
    sim.cut_link();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(30));

    assert!(sim.sent_at(A, Kind::Init).iter().all(|at| *at < secs(10)));
    assert!(sim.tunn(A).is_expired());
}

/// §6.2: if the initiator sent data on a session whose keys are older than
/// `REKEY_AFTER_TIME`, it initiates a new handshake.
#[test]
fn initiator_rekeys_when_session_is_older_than_rekey_after_time() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(A, &ipv4_packet(b"some data"));

    sim.advance(REKEY_AFTER_TIME);

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], REKEY_AFTER_TIME);
    sim.assert_connectivity();
}

/// §6.2: the original responder never initiates a rekey based on the age of
/// the session; it relies on the initiator to do so.
#[test]
fn responder_does_not_rekey_based_on_session_age() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.send_ip(B, &ipv4_packet(b"from the responder"));

    // Just short of the initiator's rekey-on-receive deadline (see below).
    sim.advance(secs(160));

    assert_eq!(sim.count(B, Kind::Init), 0);
    assert_eq!(sim.count(A, Kind::Init), 0);
    assert!(sim.is_established(B));
}

/// §6.2: having *received* data on a session older than
/// `REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT`, the initiator
/// starts a new handshake to avoid the session dying mid-conversation.
#[test]
fn initiator_rekeys_when_receiving_on_a_session_close_to_expiry() {
    let rekey_on_receive_after = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;

    let mut sim = Sim::connected();
    sim.advance(rekey_on_receive_after + secs(1));
    sim.send_ip(B, &ipv4_packet(b"late data"));
    sim.advance(secs(2));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], rekey_on_receive_after + secs(1));
    sim.assert_connectivity();
}

/// §6.1: if a peer received a data message but has not sent anything back
/// within `KEEPALIVE_TIMEOUT`, it sends a passive keepalive. The keepalive
/// counts as a reply, so it also suppresses the sender's rekey (§6.3), and it
/// must not provoke a keepalive in return.
#[test]
fn passive_keepalive_answers_unidirectional_traffic() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    sim.send_ip(A, &ipv4_packet(b"ping"));
    sim.advance(secs(30));

    let keepalives = sim.sent_at(B, Kind::Keepalive);
    assert_eq!(keepalives.len(), 1, "exactly one keepalive, no ping-pong");
    assert_close(keepalives[0], secs(1) + KEEPALIVE_TIMEOUT);

    assert_eq!(
        sim.count(A, Kind::Init),
        0,
        "keepalive suppressed the rekey"
    );
    assert_eq!(sim.count(A, Kind::Keepalive), 0);
}

/// §6.3: if a data message remains unanswered for
/// `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`, the sender assumes the session is
/// dead and initiates a new handshake. The deadline counts from the *first*
/// unanswered packet; later sends do not push it out.
#[test]
fn unanswered_data_triggers_a_new_handshake() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();

    sim.send_ip(A, &ipv4_packet(b"into the void"));
    for _ in 0..5 {
        sim.advance(secs(1));
        sim.send_ip(A, &ipv4_packet(b"more of the same"));
    }
    sim.advance(secs(11));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], secs(1) + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
}

/// §6.1: a configured persistent keepalive fires on its interval even with no
/// user traffic at all.
#[test]
fn persistent_keepalive_fires_on_its_interval() {
    let mut sim = Sim::builder().persistent_keepalive_b(25).build();
    sim.establish();
    sim.clear_log();

    sim.advance(secs(80));

    let keepalives = sim.sent_at(B, Kind::Keepalive);
    assert_eq!(keepalives.len(), 3);
    for (i, at) in keepalives.iter().enumerate() {
        assert_close(*at, secs(25) * (i as u32 + 1));
    }

    assert!(
        sim.sent_at(A, Kind::Keepalive).is_empty(),
        "keepalives are not data and must not be answered"
    );
}

/// §6.1: sessions are discarded `REJECT_AFTER_TIME` after they were
/// established. The responder simply goes silent.
#[test]
fn responder_discards_the_session_after_reject_after_time() {
    let mut sim = Sim::connected();
    sim.assert_connectivity();
    sim.advance(secs(30)); // Let passive keepalives settle.
    sim.cut_link(); // Keep the initiator's automatic renewal from re-establishing.

    sim.advance(REJECT_AFTER_TIME - secs(20));

    assert!(!sim.is_established(B));
    assert!(matches!(
        sim.try_encapsulate(B, &ipv4_packet(b"too late")),
        Err(WireGuardError::NoCurrentSession)
    ));
    assert!(
        sim.errors(B).is_empty(),
        "expiry of a session is not an error"
    );
}

/// When the expired session was initiated by us, boringtun starts a new
/// handshake right away instead of waiting for the next outgoing packet.
#[test]
fn initiator_renews_an_expired_session_automatically() {
    let mut sim = Sim::connected();
    sim.assert_connectivity();
    sim.advance(secs(30));
    sim.clear_log();

    sim.advance(REJECT_AFTER_TIME - secs(20));

    let inits = sim.sent_at(A, Kind::Init);
    assert_eq!(inits.len(), 1);
    assert_fires_at(inits[0], REJECT_AFTER_TIME);
    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// §6.1: after `3 * REJECT_AFTER_TIME` without a successful handshake, all
/// remaining state is wiped and the tunnel reports itself expired.
#[test]
fn tunnel_is_wiped_after_three_times_reject_after_time() {
    let mut sim = Sim::connected();
    sim.cut_link();

    sim.advance(3 * REJECT_AFTER_TIME + secs(2));

    assert!(sim.tunn(B).is_expired());
    assert!(sim
        .errors(B)
        .iter()
        .any(|e| matches!(e, WireGuardError::ConnectionExpired)));
}

/// boringtun-specific: the initiator refuses to *send* on a session within
/// `KEEPALIVE_TIMEOUT` of its expiry, because the packet could reach the peer
/// after the peer discarded the session.
#[test]
fn initiator_stops_sending_on_a_session_close_to_expiry() {
    let mut sim = Sim::connected();

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));

    assert!(matches!(
        sim.try_encapsulate(A, &ipv4_packet(b"risky")),
        Err(WireGuardError::NoCurrentSession)
    ));
    assert!(
        sim.is_established(A),
        "the session still exists; it is just not used for sending"
    );
}

/// The responder has no way to renew the session itself, so it keeps using it
/// right up to `REJECT_AFTER_TIME`.
#[test]
fn responder_keeps_sending_on_a_session_close_to_expiry() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"still fine");

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));
    sim.send_ip(B, &ip_packet);

    assert_eq!(sim.take_inbox(A), [ip_packet]);
}

#[cfg(feature = "packet-queue")]
#[test]
fn sending_on_a_session_close_to_expiry_starts_a_new_handshake() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"do not lose me");

    sim.advance(SHOULD_NOT_USE_AFTER_TIME + secs(1));

    let init = sim
        .encapsulate_or_queue(A, &ip_packet)
        .expect("a handshake initiation instead of a data message");
    assert_eq!(crate::harness::classify(&init), Kind::Init);

    sim.route(A, init);

    assert_eq!(
        sim.take_inbox(B),
        [ip_packet],
        "the packet survived the rekey"
    );
}

/// Repeated rekeying rotates through the (eight-slot) session ring without
/// dropping connectivity.
#[test]
fn repeated_rekeys_do_not_disturb_connectivity() {
    let mut sim = Sim::connected();

    for _ in 0..12 {
        sim.advance(secs(1));
        let init = sim.initiate_handshake(A);
        sim.route(A, init);
        sim.assert_connectivity();
    }
}

/// §6.1 (transition period): right after a rekey, data encrypted under the
/// previous session must still decrypt until the peer switches over.
#[test]
fn previous_session_remains_usable_during_rekey_transition() {
    let mut sim = Sim::connected();
    sim.assert_connectivity();
    sim.advance(secs(1));

    // Complete a new handshake but hold back the confirming keepalive.
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let keepalive = sim.deliver(A, &response).expect_one_net();

    // B has not seen traffic on the new session and keeps using the old one.
    let old_data = sim.encapsulate(B, &ipv4_packet(b"old session"));
    sim.deliver(A, &old_data).expect_one_ip();

    // Once the keepalive arrives, B switches to the new session.
    sim.deliver(B, &keepalive).expect_consumed();
    let new_data = sim.encapsulate(B, &ipv4_packet(b"new session"));
    assert_ne!(
        crate::harness::receiver_index(&old_data),
        crate::harness::receiver_index(&new_data)
    );
    sim.deliver(A, &new_data).expect_one_ip();
}
