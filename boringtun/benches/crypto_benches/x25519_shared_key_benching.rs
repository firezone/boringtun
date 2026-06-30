use criterion::{BatchSize, Criterion};

pub fn bench_x25519_shared_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_shared_key");

    group.sample_size(1000);

    group.bench_function("x25519_shared_key_dalek", |b| {
        let public_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random());

        b.iter_batched(
            || x25519_dalek::StaticSecret::random(),
            |secret_key| secret_key.diffie_hellman(&public_key),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("x25519_shared_key_aws_lc_rs", |b| {
        let rng = aws_lc_rs::rand::SystemRandom::new();

        let peer_public_key = {
            let peer_private_key = aws_lc_rs::agreement::EphemeralPrivateKey::generate(
                &aws_lc_rs::agreement::X25519,
                &rng,
            )
            .unwrap();
            peer_private_key.compute_public_key().unwrap()
        };
        let peer_public_key_alg = &aws_lc_rs::agreement::X25519;

        let my_public_key =
            aws_lc_rs::agreement::UnparsedPublicKey::new(peer_public_key_alg, &peer_public_key);

        b.iter_batched(
            || {
                aws_lc_rs::agreement::EphemeralPrivateKey::generate(
                    &aws_lc_rs::agreement::X25519,
                    &rng,
                )
                .unwrap()
            },
            |my_private_key| {
                aws_lc_rs::agreement::agree_ephemeral(
                    my_private_key,
                    my_public_key,
                    aws_lc_rs::error::Unspecified,
                    |_key_material| Ok::<(), aws_lc_rs::error::Unspecified>(()),
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}
