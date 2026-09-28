use criterion::{BenchmarkId, Criterion, Throughput};
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

fn aes256gcm_ring(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key_bytes).unwrap());

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf[..n],
        )
        .unwrap();

    buf[n..].copy_from_slice(tag.as_ref())
}

pub fn bench_aes256gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256gcm");

    group.sample_size(1000);

    for size in [128, 192, 1400, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("aes256gcm_ring", size), &size, |b, i| {
            let mut key = [0; 32];
            let mut buf = vec![0; i + 16];

            let mut rng = rand::rng();

            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut buf);

            b.iter(|| aes256gcm_ring(&key, &mut buf));
        });
    }

    group.finish();
}
