//! Transport data messages (whitepaper §5.4.6): encryption overhead,
//! keepalives, tampering and validation of the decrypted payload.

use crate::harness::{
    ipv4_packet, ipv6_packet, Outcome as _, Peer::A, Peer::B, Sim, DATA_OVERHEAD, KEEPALIVE_SIZE,
};
use boringtun::noise::errors::WireGuardError;

#[test]
fn ipv4_packets_round_trip() {
    let mut sim = Sim::connected();

    sim.assert_connectivity();
}

#[test]
fn ipv6_packets_round_trip() {
    let mut sim = Sim::connected();
    let ip_packet = ipv6_packet(b"hello v6");

    sim.send_ip(A, &ip_packet);

    assert_eq!(sim.take_inbox(B), [ip_packet]);
}

#[test]
fn data_messages_have_32_bytes_of_overhead() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"some payload");

    let datagram = sim.encapsulate(A, &ip_packet);

    assert_eq!(datagram.len(), ip_packet.len() + DATA_OVERHEAD);
}

// §6.1: a keepalive is a data message with a zero-length payload; it proves
// liveness but is not forwarded to the tunnel interface.
#[test]
fn keepalives_are_consumed_silently() {
    let mut sim = Sim::connected();

    let keepalive = sim.encapsulate(A, &[]);
    assert_eq!(keepalive.len(), KEEPALIVE_SIZE);

    sim.deliver(B, &keepalive).expect_consumed();
    assert!(sim.take_inbox(B).is_empty());
}

#[test]
fn tampered_data_packet_is_rejected() {
    let mut sim = Sim::connected();

    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    *datagram.last_mut().unwrap() ^= 1;

    let error = sim.deliver(B, &datagram).expect_err();

    assert!(matches!(error, WireGuardError::InvalidAeadTag));
    assert!(sim.take_inbox(B).is_empty());
}

#[test]
fn data_with_wrong_receiver_index_is_rejected() {
    let mut sim = Sim::connected();

    // Same session slot, different index: decryption is never attempted.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    let index = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
    datagram[4..8].copy_from_slice(&(index + 8).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, WireGuardError::WrongIndex));

    // Index pointing at an empty session slot.
    let mut datagram = sim.encapsulate(A, &ipv4_packet(b"payload"));
    datagram[4..8].copy_from_slice(&(index + 6).to_le_bytes());
    let error = sim.deliver(B, &datagram).expect_err();
    assert!(matches!(error, WireGuardError::NoCurrentSession));
}

// The receiver validates that the decrypted payload is a plausible IP packet
// before handing it to the tunnel interface.
#[test]
fn non_ip_payload_is_rejected_after_decryption() {
    let mut sim = Sim::connected();

    let datagram = sim.encapsulate(A, b"?");

    let error = sim.deliver(B, &datagram).expect_err();

    assert!(matches!(error, WireGuardError::InvalidPacket));
}

// §5.4.6: encrypted packets are padded; the receiver must truncate the
// plaintext to the length declared in the IP header.
#[test]
fn decrypted_packets_are_truncated_to_their_ip_length_field() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"payload");

    let mut padded = ip_packet.clone();
    padded.extend_from_slice(&[0u8; 13]);
    let datagram = sim.encapsulate(A, &padded);

    let received = sim.deliver(B, &datagram).expect_one_ip();

    assert_eq!(received, ip_packet);
}

#[test]
fn ip_packet_claiming_more_than_its_size_is_rejected() {
    let mut sim = Sim::connected();

    let mut ip_packet = ipv4_packet(b"payload");
    ip_packet.truncate(ip_packet.len() - 2); // Now shorter than its length field claims.
    let datagram = sim.encapsulate(A, &ip_packet);

    let error = sim.deliver(B, &datagram).expect_err();

    assert!(matches!(error, WireGuardError::InvalidPacket));
}
