//! The 1-RTT handshake (whitepaper §5.4): message flow, authentication
//! failures and replay of handshake messages.

use crate::harness::{
    classify, Kind, Outcome as _, Peer::A, Peer::B, Sim, HANDSHAKE_INIT_SIZE,
    HANDSHAKE_RESPONSE_SIZE,
};
use boringtun::noise::errors::WireGuardError;

#[test]
fn handshake_completes_in_one_round_trip() {
    let mut sim = Sim::new();

    sim.establish();

    // §6.5: the first message of the initiator on the new session confirms
    // the key to the responder; with nothing to send, that is a keepalive.
    let flow = sim
        .log
        .iter()
        .map(|event| (event.from, event.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        flow,
        [(A, Kind::Init), (B, Kind::Response), (A, Kind::Keepalive)]
    );

    sim.assert_connectivity();
}

#[test]
fn handshake_messages_have_the_sizes_mandated_by_the_paper() {
    let mut sim = Sim::new();

    let init = sim.initiate_handshake(A);
    assert_eq!(init.len(), HANDSHAKE_INIT_SIZE); // §5.4.2

    let response = sim.deliver(B, &init).expect_one_net();
    assert_eq!(response.len(), HANDSHAKE_RESPONSE_SIZE); // §5.4.3
}

#[test]
fn handshake_with_matching_preshared_key_succeeds() {
    let psk = [0x42; 32];
    let mut sim = Sim::builder().psk_a(psk).psk_b(psk).build();

    sim.establish();
    sim.assert_connectivity();
}

// §5.4.4: the PSK is mixed into the key derivation of the response, so a
// mismatch surfaces as an unopenable response on the initiator.
#[test]
fn handshake_with_mismatched_preshared_key_fails() {
    let mut sim = Sim::builder().psk_a([0x42; 32]).build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);

    assert!(!sim.is_established(A));
    assert!(!sim.is_established(B));
    assert!(matches!(sim.errors(A), [WireGuardError::InvalidAeadTag]));
}

#[test]
fn responder_rejects_initiator_with_unexpected_static_key() {
    let mut sim = Sim::builder().responder_expects_different_key().build();

    let init = sim.initiate_handshake(A);
    sim.route(A, init);

    assert!(matches!(sim.errors(B), [WireGuardError::WrongKey]));
    assert_eq!(
        sim.count(B, Kind::Response),
        0,
        "responder must stay silent"
    );
    assert!(!sim.is_established(B));
}

// §5.1 / §5.4.2: the encrypted TAI64N timestamp protects against replay of
// handshake initiations.
#[test]
fn replayed_handshake_initiation_is_rejected() {
    let mut sim = Sim::new();

    let init = sim.initiate_handshake(A);
    sim.deliver(B, &init).expect_one_net();

    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, WireGuardError::WrongTai64nTimestamp));
}

// boringtun keeps two outgoing handshakes in flight so that a delayed
// response to an earlier initiation is not lost on flaky networks.
#[test]
fn delayed_response_to_a_superseded_initiation_is_accepted() {
    let mut sim = Sim::new();

    let first_init = sim.initiate_handshake(A);
    sim.advance(crate::harness::secs(1));
    let _second_init = sim.force_handshake_initiation(A);

    // The *first* initiation reaches the responder, whose response must still
    // complete the handshake on the initiator.
    sim.route(A, first_init);

    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

#[test]
fn simultaneous_handshake_initiations_converge() {
    let mut sim = Sim::new();

    let init_a = sim.initiate_handshake(A);
    let init_b = sim.initiate_handshake(B);
    sim.route(A, init_a);
    sim.route(B, init_b);

    assert!(sim.is_established(A));
    assert!(sim.is_established(B));
    sim.assert_connectivity();
}

#[test]
fn tampered_handshake_initiation_is_rejected() {
    let mut sim = Sim::new();

    let mut init = sim.initiate_handshake(A);
    init[100] ^= 1; // Any bit flip up to mac1 must invalidate mac1 (§5.4.4).

    let error = sim.deliver(B, &init).expect_err();

    assert!(matches!(error, WireGuardError::InvalidMac));
}

#[test]
fn cookie_reply_out_of_the_blue_is_rejected() {
    let mut sim = Sim::new();

    // A valid-looking cookie reply (type 3, 64 bytes) without a preceding
    // handshake from us must not be accepted.
    let mut cookie_reply = vec![0u8; 64];
    cookie_reply[0] = 3;

    let error = sim.deliver(B, &cookie_reply).expect_err();

    assert!(matches!(error, WireGuardError::UnexpectedPacket));
}

#[test]
fn malformed_datagrams_are_rejected() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);

    for garbage in [
        &[1u8, 2, 3] as &[u8],   // too short to even carry a message type
        &[0xff; 148],            // unknown message type
        &init[..init.len() - 1], // truncated handshake initiation
    ] {
        let error = sim.deliver(B, garbage).expect_err();

        assert!(matches!(error, WireGuardError::InvalidPacket));
    }

    let kind = classify(&init);
    assert_eq!(kind, Kind::Init, "the untampered packet parses fine");
}
