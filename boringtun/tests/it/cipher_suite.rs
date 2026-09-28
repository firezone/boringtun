//! Peers speaking `Noise_IKpsk2_25519_AESGCM_BLAKE2s` instead of WireGuard's
//! `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.

use crate::harness::{Kind, Peer::A, Peer::B, Sim};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::CipherSuite;

#[test]
fn aes_gcm_peers_complete_handshake_and_exchange_data() {
    let mut sim = Sim::builder()
        .cipher_suites(CipherSuite::AesGcm, CipherSuite::AesGcm)
        .build();

    sim.establish();

    sim.assert_connectivity();
    sim.assert_connectivity();
}

// The protocol name seeds the handshake hash, so the responder cannot even
// decrypt the initiator's static key.
#[test]
fn mismatched_cipher_suites_fail_at_the_handshake() {
    for (a, b) in [
        (CipherSuite::AesGcm, CipherSuite::ChaChaPoly),
        (CipherSuite::ChaChaPoly, CipherSuite::AesGcm),
    ] {
        let mut sim = Sim::builder().cipher_suites(a, b).build();

        let init = sim.initiate_handshake(A);
        sim.route(A, init);

        assert!(matches!(sim.errors(B), [WireGuardError::InvalidAeadTag]));
        assert_eq!(sim.count(B, Kind::Response), 0);
        assert!(!sim.is_established(A));
        assert!(!sim.is_established(B));
    }
}
