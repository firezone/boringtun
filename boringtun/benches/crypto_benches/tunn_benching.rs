use std::time::{Duration, Instant};

use boringtun::noise::{Index, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};

/// WireGuard data message overhead (4 type + 4 receiver + 8 counter + 16 tag).
const DATA_OVERHEAD: usize = 32;

/// Size of the "cold" working set. Chosen to exceed a typical last-level cache so that each rotated
/// packet is fetched from RAM rather than served from L1/L2/L3, modelling a freshly-arrived packet.
const COLD_POOL_BYTES: usize = 128 << 20;

/// Establish two tunnels and complete a full handshake so the returned `(initiator, responder)`
/// pair has a usable session for `encapsulate_data_at` / `decapsulate_at`.
fn handshaked_pair(now: Instant) -> (Tunn, Tunn) {
    let my_secret = StaticSecret::random();
    let my_public = PublicKey::from(&my_secret);
    let their_secret = StaticSecret::random();
    let their_public = PublicKey::from(&their_secret);

    let mut my_tun = Tunn::new_at(
        my_secret,
        their_public,
        None,
        None,
        Index::new_local(1),
        None,
        0,
        now,
        now,
        Duration::ZERO,
    );
    let mut their_tun = Tunn::new_at(
        their_secret,
        my_public,
        None,
        None,
        Index::new_local(2),
        None,
        0,
        now,
        now,
        Duration::ZERO,
    );

    let mut buf = vec![0u8; 2048];

    let init = match my_tun.format_handshake_initiation_at(&mut buf, false, now) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected handshake init, got {other:?}"),
    };
    let resp = match their_tun.decapsulate_at(None, &init, &mut buf, now) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected handshake response, got {other:?}"),
    };
    let keepalive = match my_tun.decapsulate_at(None, &resp, &mut buf, now) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected keepalive, got {other:?}"),
    };
    match their_tun.decapsulate_at(None, &keepalive, &mut buf, now) {
        TunnResult::Done => {}
        other => panic!("expected done, got {other:?}"),
    }

    (my_tun, their_tun)
}

/// Writes a minimal valid IPv4 packet of `len` bytes into `slot` (version nibble + total-length
/// field, the only things `validate_decapsulated_packet` checks), with a `seed`-varied payload so no
/// two packets in the pool share content.
fn fill_ipv4(slot: &mut [u8], len: usize, seed: usize) {
    slot[0] = 0x45; // version 4, IHL 5
    let total = (len as u16).to_be_bytes();
    slot[2] = total[0];
    slot[3] = total[1];
    for (i, b) in slot.iter_mut().enumerate().take(len).skip(20) {
        *b = (seed.wrapping_add(i)) as u8;
    }
}

/// Largest power-of-two slot count whose packets of `stride` bytes fill `COLD_POOL_BYTES`.
fn cold_slots(stride: usize) -> usize {
    let max = (COLD_POOL_BYTES / stride).max(2);
    1usize << max.ilog2()
}

/// Bijective pseudo-random index in `0..=mask` (mask must be `2^k - 1`). Visiting `0, 1, 2, ...`
/// through this scramble walks every slot in a cache- and prefetcher-hostile order.
#[inline]
fn scramble(counter: usize, mask: usize) -> usize {
    counter.wrapping_mul(0x9E37_79B1) & mask
}

pub fn bench_tunn(c: &mut Criterion) {
    // A fixed logical `now` keeps the session usable (it never expires) across all iterations.
    let now = Instant::now();

    let mut group = c.benchmark_group("tunn");

    for size in [128usize, 1400] {
        group.throughput(Throughput::Bytes(size as u64));

        // --- HOT: one reused source/destination buffer (stays in L1). ---
        group.bench_with_input(BenchmarkId::new("encapsulate_hot", size), &size, |b, &size| {
            let (mut my_tun, _their_tun) = handshaked_pair(now);
            let mut packet = vec![0u8; size];
            fill_ipv4(&mut packet, size, 0);
            let mut dst = vec![0u8; size + DATA_OVERHEAD + 64];

            b.iter(|| {
                my_tun
                    .encapsulate_data_at(&packet, &mut dst, now)
                    .expect("a usable session exists after the handshake")
            });
        });

        // --- COLD: rotate src+dst through a >LLC pool in scrambled order (RAM-cold, varied). ---
        group.bench_with_input(BenchmarkId::new("encapsulate_cold", size), &size, |b, &size| {
            let (mut my_tun, _their_tun) = handshaked_pair(now);
            let slots = cold_slots(size + DATA_OVERHEAD + 64);
            let mask = slots - 1;
            let src_stride = size;
            let dst_stride = size + DATA_OVERHEAD + 64;

            let mut src = vec![0u8; slots * src_stride];
            let mut dst = vec![0u8; slots * dst_stride];
            for s in 0..slots {
                let o = s * src_stride;
                fill_ipv4(&mut src[o..o + src_stride], size, s);
            }

            let mut counter = 0usize;
            b.iter(|| {
                let s = scramble(counter, mask);
                counter = counter.wrapping_add(1);
                let so = s * src_stride;
                let d_o = s * dst_stride;
                my_tun
                    .encapsulate_data_at(&src[so..so + size], &mut dst[d_o..d_o + dst_stride], now)
                    .expect("a usable session exists after the handshake")
            });
        });

        // Decapsulate a data packet over an established session. Each decapsulation needs a fresh
        // counter, so the (untimed) setup encapsulates a new packet (from a rotating cold,
        // content-varied source) and we time only the decap of the freshly produced ciphertext.
        group.bench_with_input(BenchmarkId::new("decapsulate", size), &size, |b, &size| {
            let (mut my_tun, mut their_tun) = handshaked_pair(now);
            let slots = cold_slots(size);
            let mask = slots - 1;
            let src_stride = size;
            let mut src = vec![0u8; slots * src_stride];
            for s in 0..slots {
                let o = s * src_stride;
                fill_ipv4(&mut src[o..o + src_stride], size, s);
            }
            let mut wg = vec![0u8; size + DATA_OVERHEAD + 64];
            let mut out = vec![0u8; size + DATA_OVERHEAD + 64];
            let mut counter = 0usize;

            b.iter_batched(
                || {
                    let s = scramble(counter, mask);
                    counter = counter.wrapping_add(1);
                    let so = s * src_stride;
                    let len = my_tun
                        .encapsulate_data_at(&src[so..so + size], &mut wg, now)
                        .unwrap();
                    wg[..len].to_vec()
                },
                |data| match their_tun.decapsulate_at(None, &data, &mut out, now) {
                    TunnResult::WriteToTunnelV4(..) => {}
                    other => panic!("unexpected decapsulate result: {other:?}"),
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}
