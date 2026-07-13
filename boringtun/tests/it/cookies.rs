//! Cookie-based DoS mitigation (whitepaper §5.3): a responder under load
//! answers handshakes with a cookie reply instead of doing expensive
//! computation, and only proceeds once the initiator proves IP ownership by
//! echoing the cookie in mac2.

use crate::harness::{
    classify, secs, Kind, Outcome as _, Peer::A, Peer::B, Sim, COOKIE_EXPIRATION_TIME,
    COOKIE_REPLY_SIZE,
};
use boringtun::noise::errors::WireGuardError;

#[test]
fn responder_under_load_replies_with_a_cookie_instead_of_a_handshake() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    let reply = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&reply), Kind::CookieReply);
    assert_eq!(reply.len(), COOKIE_REPLY_SIZE); // §5.4.7
    assert!(!sim.is_established(B), "no session state was created");
}

/// The initiator stores the received cookie and its next (retransmitted)
/// initiation carries a valid mac2, which the loaded responder accepts.
#[test]
fn handshake_completes_under_load_via_cookie_retry() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    assert!(
        !sim.is_established(A),
        "first attempt only yielded a cookie"
    );

    // The regular REKEY_TIMEOUT retransmission carries mac2.
    sim.advance(secs(6));

    assert_eq!(sim.count(B, Kind::CookieReply), 1);
    assert_eq!(sim.count(B, Kind::Response), 1);
    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

/// §5.3: mac2 is keyed on the initiator's transport address, so a responder
/// under load cannot make progress without knowing the packet's source.
#[test]
fn handshake_without_source_address_fails_under_load() {
    let mut sim = Sim::builder().responder_under_load().build();

    let init = sim.initiate_handshake(A);
    let error = sim.deliver_anonymous(B, &init).expect_err();

    assert!(matches!(error, WireGuardError::UnderLoad));
}

/// A cookie stays valid for two minutes; within that window new handshakes
/// keep using it and are accepted straight away.
#[test]
fn fresh_cookie_is_reused_for_subsequent_handshakes() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(6)); // Complete the handshake via the cookie retry.

    sim.advance(secs(30));
    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&response), Kind::Response);
}

/// §5.3 / §6.1: cookies are discarded after `COOKIE_EXPIRATION_TIME`; a later
/// handshake is back to square one and gets a fresh cookie reply.
#[test]
fn expired_cookie_forces_a_new_cookie_round_trip() {
    let mut sim = Sim::builder().responder_under_load().build();
    let init = sim.initiate_handshake(A);
    sim.route(A, init);
    sim.advance(secs(6));
    assert!(sim.is_established(A));

    sim.advance(COOKIE_EXPIRATION_TIME);
    let init = sim.force_handshake_initiation(A);
    let reply = sim.deliver(B, &init).expect_one_net();

    assert_eq!(classify(&reply), Kind::CookieReply);
}

/// With its own rate limiter, a tunnel considers itself under load beyond 10
/// handshake messages per second and recovers once the flood stops.
#[test]
fn rate_limited_tunnel_recovers_once_load_subsides() {
    let mut sim = Sim::new();

    for _ in 0..10 {
        let init = sim.force_handshake_initiation(A);
        sim.deliver(B, &init).expect_one_net();
        sim.now += std::time::Duration::from_millis(10);
    }

    let init = sim.force_handshake_initiation(A);
    let reply = sim.deliver(B, &init).expect_one_net();
    assert_eq!(
        classify(&reply),
        Kind::CookieReply,
        "11th handshake within a second"
    );

    sim.advance(secs(2)); // The rate limiter resets its counter every second.

    let init = sim.force_handshake_initiation(A);
    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(classify(&response), Kind::Response);
}
