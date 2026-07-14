//! Contracts specific to the sans-IO design: callers inject time explicitly,
//! learn when to call back via `next_timer_update`, and must get identical
//! behaviour for identical inputs.

use crate::harness::{
    classify, ipv4_packet, secs, Kind, Outcome as _, Peer::A, Peer::B, Sim, KEEPALIVE_SIZE,
    KEEPALIVE_TIMEOUT, MAX_JITTER, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT,
};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::TunnResult;
use std::time::Duration;

/// A handshake triggered by a timer is not sent immediately: it is scheduled
/// with a random jitter of up to 333ms, announced via `next_timer_update` and
/// emitted exactly once when that deadline is polled.
#[test]
fn scheduled_handshake_honours_next_timer_update() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));
    sim.cut_link();
    sim.send_ip(A, &ipv4_packet(b"unanswered"));

    let deadline = sim.now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
    let tunn = sim.tunn_mut(A);
    let mut buf = [0u8; 256];

    // Nothing is due before the deadline.
    assert!(matches!(
        tunn.update_timers_at(&mut buf, deadline - Duration::from_millis(1)),
        TunnResult::Done
    ));

    // At the deadline, the handshake is only *scheduled* ...
    assert!(matches!(
        tunn.update_timers_at(&mut buf, deadline),
        TunnResult::Done
    ));
    let (wake, _reason) = tunn.next_timer_update().expect("a scheduled handshake");
    assert!(wake >= deadline && wake <= deadline + MAX_JITTER);

    // ... and emitted exactly once when the announced instant is polled.
    let TunnResult::WriteToNetwork(packet) = tunn.update_timers_at(&mut buf, wake) else {
        panic!("expected the scheduled handshake initiation");
    };
    assert_eq!(classify(packet), Kind::Init);
    assert!(matches!(
        tunn.update_timers_at(&mut buf, wake),
        TunnResult::Done
    ));
}

#[test]
fn next_timer_update_predicts_the_passive_keepalive() {
    let mut sim = Sim::connected();
    sim.advance(secs(1));

    let datagram = sim.encapsulate(A, &ipv4_packet(b"ping"));
    sim.deliver(B, &datagram).expect_one_ip();
    let received_at = sim.now;

    let tunn = sim.tunn_mut(B);
    let (wake, _reason) = tunn.next_timer_update().expect("a pending keepalive");
    assert_eq!(wake, received_at + KEEPALIVE_TIMEOUT);

    let mut buf = [0u8; 256];
    assert!(matches!(
        tunn.update_timers_at(&mut buf, wake - Duration::from_millis(1)),
        TunnResult::Done
    ));
    let TunnResult::WriteToNetwork(packet) = tunn.update_timers_at(&mut buf, wake) else {
        panic!("expected the keepalive");
    };
    assert_eq!(packet.len(), KEEPALIVE_SIZE);

    // The passive keepalive has been answered, so it must not re-arm; the only
    // thing left on the clock is the eventual session expiry.
    let (_wake, reason) = tunn
        .next_timer_update()
        .expect("a session that still expires eventually");
    assert_eq!(reason, "next expired session");
}

/// `next_timer_update` must never announce an instant in the past. Timers are
/// anchored to the session start, so sending on a session already older than
/// `REKEY_AFTER_TIME` arms the rekey-on-send timer with a deadline that has
/// already elapsed; the caller must still be handed a usable (not past) instant.
#[test]
fn next_timer_update_never_points_into_the_past() {
    let mut sim = Sim::connected();

    // Age the session past REKEY_AFTER_TIME. With no traffic, nothing rekeys, so
    // the session is still alive and its start is now well over REKEY_AFTER_TIME
    // in the past.
    sim.advance(REKEY_AFTER_TIME + secs(1));

    // Sending now arms the rekey-on-send timer, whose deadline (session start +
    // REKEY_AFTER_TIME) is already behind us.
    sim.send_ip(A, &ipv4_packet(b"traffic after a long silence"));

    let (wake, _reason) = sim.tunn(A).next_timer_update().expect("a rekey is now due");
    assert!(
        wake >= sim.now,
        "next_timer_update returned an instant {:?} before now",
        sim.now.duration_since(wake),
    );
}

/// Callers may poll arbitrarily rarely; a single call after a long gap must
/// still observe the (by then) expired state instead of panicking or hanging.
#[test]
fn a_single_late_poll_observes_the_expiry() {
    let mut sim = Sim::connected();

    let late = sim.now + 4 * REJECT_AFTER_TIME;
    let mut buf = [0u8; 256];
    let result = sim.tunn_mut(A).update_timers_at(&mut buf, late);

    assert!(matches!(
        result,
        TunnResult::Err(WireGuardError::ConnectionExpired)
    ));
    assert!(sim.tunn(A).is_expired());
}

/// The only source of randomness in timer behaviour is the seeded jitter RNG:
/// identical seeds must produce identical retransmission schedules.
#[test]
fn identical_seeds_produce_identical_schedules() {
    fn retransmissions(seed: u64) -> Vec<Duration> {
        let mut sim = Sim::builder().seeds(seed, seed.wrapping_add(1)).build();
        sim.cut_link();
        let init = sim.initiate_handshake(A);
        sim.route(A, init);
        sim.advance(secs(30));
        sim.sent_at(A, Kind::Init)
    }

    assert_eq!(retransmissions(7), retransmissions(7));
}

#[test]
fn different_seeds_produce_different_jitter() {
    fn first_jitter(seed: u64) -> Duration {
        let mut sim = Sim::builder().seeds(seed, 99).build();
        let _init = sim.initiate_handshake(A);

        // Once REKEY_TIMEOUT passes, a retry is scheduled `jitter` in the future.
        let retry_due = sim.now + REKEY_TIMEOUT;
        let mut buf = [0u8; 256];
        let tunn = sim.tunn_mut(A);
        assert!(matches!(
            tunn.update_timers_at(&mut buf, retry_due),
            boringtun::noise::TunnResult::Done
        ));

        tunn.next_timer_update()
            .expect("a scheduled retry")
            .0
            .duration_since(retry_due)
    }

    assert_eq!(first_jitter(1), first_jitter(1));
    assert_ne!(first_jitter(1), first_jitter(2));
}

/// `encapsulate_data_at` is advertised as side-effect free when no session
/// exists: no packet is queued and no handshake is started.
#[test]
fn encapsulate_data_at_has_no_side_effects_without_a_session() {
    let mut sim = Sim::new();

    let result = sim.try_encapsulate(A, &ipv4_packet(b"no session yet"));
    assert!(matches!(result, Err(WireGuardError::NoCurrentSession)));

    sim.advance(secs(10)); // Well past REKEY_TIMEOUT.

    assert!(sim.log.is_empty(), "no handshake may have been initiated");
}
