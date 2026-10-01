//! Deferred encryption of data messages: all state changes happen on the
//! `Tunn`, in order, while the AEAD work may run later, in any order and on
//! any thread.

use crate::harness::{ipv4_packet, Outcome as _, Peer::A, Peer::B, Sim};

const BUF: usize = 4096;

#[test]
fn deferred_seal_matches_the_eager_path() {
    let mut sim = Sim::connected();
    let ip_packet = ipv4_packet(b"sealed later");
    let now = sim.now;

    let mut datagram = vec![0u8; BUF];
    let seal = sim
        .tunn_mut(A)
        .encapsulate_data_deferred_at(&ip_packet, &mut datagram, now)
        .unwrap();
    let len = seal.seal(&mut datagram);
    datagram.truncate(len);

    assert_eq!(len, sim.encapsulate(A, &ip_packet).len());
    assert_eq!(sim.deliver(B, &datagram).expect_one_ip(), ip_packet);
}

#[test]
fn seals_running_out_of_order_keep_their_counters() {
    let mut sim = Sim::connected();
    let ip_packets = (0..3).map(|i| ipv4_packet(&[i])).collect::<Vec<_>>();
    let now = sim.now;

    let mut datagrams = Vec::new();
    let mut seals = Vec::new();
    for ip_packet in &ip_packets {
        let mut datagram = vec![0u8; BUF];
        let seal = sim
            .tunn_mut(A)
            .encapsulate_data_deferred_at(ip_packet, &mut datagram, now)
            .unwrap();
        datagrams.push(datagram);
        seals.push(seal);
    }
    for (seal, datagram) in seals.into_iter().zip(&mut datagrams).rev() {
        let len = seal.seal(datagram);
        datagram.truncate(len);
    }

    let counters = datagrams.iter().map(|d| counter(d)).collect::<Vec<_>>();
    assert!(counters.is_sorted());
    for (datagram, ip_packet) in datagrams.iter().zip(&ip_packets) {
        assert_eq!(&sim.deliver(B, datagram).expect_one_ip(), ip_packet);
    }
}

fn counter(datagram: &[u8]) -> u64 {
    u64::from_le_bytes(datagram[8..16].try_into().unwrap())
}
