//! Deferred encryption and decryption of data messages: all state changes
//! happen on the `Tunn`, in order, while the AEAD work may run later, in any
//! order and on any thread.

use crate::harness::{ipv4_packet, Outcome as _, Peer::A, Peer::B, Sim, REPLAY_WINDOW};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Opened, Packet, PendingOpen, Tunn, TunnResult};
use std::time::Instant;

const BUF: usize = 4096;

#[test]
fn deferred_seal_matches_the_eager_path() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"sealed later");
    let now = sim.now;

    let seal = sim
        .tunn_mut(A)
        .encapsulate_data_deferred_at(ip_packet.len(), now)
        .unwrap();
    let mut datagram = vec![0u8; BUF];
    let len = seal.seal_into(&ip_packet, &mut datagram);
    datagram.truncate(len);

    assert_eq!(len, sim.encapsulate(A, &ip_packet).len());
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn seals_running_out_of_order_keep_their_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let now = sim.now;

    let seals = ip_packets
        .iter()
        .map(|ip_packet| {
            sim.tunn_mut(A)
                .encapsulate_data_deferred_at(ip_packet.len(), now)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut datagrams = seals
        .into_iter()
        .zip(&ip_packets)
        .rev()
        .map(|(seal, ip_packet)| {
            let mut datagram = vec![0u8; BUF];
            let len = seal.seal_into(ip_packet, &mut datagram);
            datagram.truncate(len);

            datagram
        })
        .collect::<Vec<_>>();
    datagrams.reverse();

    let counters = datagrams.iter().map(|d| counter(d)).collect::<Vec<_>>();
    assert!(counters.is_sorted());
    for (datagram, ip_packet) in datagrams.iter().zip(&ip_packets) {
        assert_eq!(&sim.deliver(B, datagram).expect_one_ip(), ip_packet);
    }
}

#[test]
fn deferred_open_matches_the_eager_path() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"opened later");
    let eager = sim.encapsulate(A, &ip_packet);
    let deferred = sim.encapsulate(A, &ip_packet);
    let now = sim.now;

    let eager = sim.deliver(B, &eager).expect_one_ip();
    let mut buf = vec![0u8; BUF];
    let opened = prepare_open(sim.tunn_mut(B), &deferred, &mut buf)
        .unwrap()
        .open(&mut buf);
    let deferred = finish_open(sim.tunn_mut(B), opened, &mut buf, now);

    assert_eq!(deferred.unwrap(), eager);
}

#[test]
fn duplicate_within_one_batch_is_accepted_only_once() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"twice");
    let datagram = sim.encapsulate(A, &ip_packet);
    let now = sim.now;
    let tunn = sim.tunn_mut(B);

    let mut first_buf = vec![0u8; BUF];
    let mut second_buf = vec![0u8; BUF];
    let first = prepare_open(tunn, &datagram, &mut first_buf).unwrap();
    let second = prepare_open(tunn, &datagram, &mut second_buf).unwrap();
    let first = first.open(&mut first_buf);
    let second = second.open(&mut second_buf);

    assert_eq!(
        finish_open(tunn, first, &mut first_buf, now).unwrap(),
        ip_packet
    );
    assert!(matches!(
        finish_open(tunn, second, &mut second_buf, now),
        Err(WireGuardError::DuplicateCounter)
    ));
}

#[test]
fn tampered_packet_does_not_advance_the_replay_window() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"");
    let datagrams = (0..REPLAY_WINDOW + 2)
        .map(|_| sim.encapsulate(A, &ip_packet))
        .collect::<Vec<_>>();
    let mut tampered = datagrams.last().unwrap().clone();
    *tampered.last_mut().unwrap() ^= 1;
    let now = sim.now;

    let mut buf = vec![0u8; BUF];
    let opened = prepare_open(sim.tunn_mut(B), &tampered, &mut buf)
        .unwrap()
        .open(&mut buf);
    let result = finish_open(sim.tunn_mut(B), opened, &mut buf, now);

    assert!(matches!(result, Err(WireGuardError::InvalidAeadTag)));
    assert_eq!(sim.deliver(B, &datagrams[0]).expect_one_ip(), ip_packet);
}

#[test]
fn handshake_response_leaves_the_keepalive_to_the_caller() {
    let mut sim = Sim::new();
    let init = sim.initiate_handshake(A);
    let response = sim.deliver(B, &init).expect_one_net();
    let now = sim.now;

    let mut buf = vec![0u8; BUF];
    let result = sim
        .tunn_mut(A)
        .decapsulate_at(None, &response, &mut buf, now);
    assert!(matches!(result, TunnResult::KeepaliveDue));

    let keepalive = sim.encapsulate(A, &[]);
    sim.deliver(B, &keepalive).expect_consumed();
    sim.assert_connectivity();
}

fn prepare_open(
    tunn: &mut Tunn,
    datagram: &[u8],
    buf: &mut [u8],
) -> Result<PendingOpen, WireGuardError> {
    let Packet::PacketData(data) = Tunn::parse_incoming_packet(datagram)? else {
        panic!("expected a data message");
    };

    tunn.decapsulate_data_deferred(data, buf)
}

fn finish_open(
    tunn: &mut Tunn,
    opened: Opened,
    buf: &mut [u8],
    now: Instant,
) -> Result<Vec<u8>, WireGuardError> {
    match tunn.finish_decapsulate_data_at(opened, buf, now) {
        TunnResult::WriteToTunnelV4(packet, _) => Ok(packet.to_vec()),
        TunnResult::Err(e) => Err(e),
        other => panic!("expected an IPv4 packet or an error, got {other:?}"),
    }
}

fn counter(datagram: &[u8]) -> u64 {
    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}
