use std::sync::LazyLock;

use ring::aead::{Algorithm, AES_256_GCM, CHACHA20_POLY1305};

use super::handshake::b2s_hash;

/// The Noise protocol spoken between two [`Tunn`](super::Tunn)s.
///
/// Both peers must use the same suite.
/// The protocol name seeds the handshake, so peers with different suites fail to complete it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    /// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, i.e. standard WireGuard.
    #[default]
    ChaChaPoly,
    /// `Noise_IKpsk2_25519_AESGCM_BLAKE2s`, using AES-256-GCM.
    ///
    /// Only faster than [`CipherSuite::ChaChaPoly`] on CPUs with hardware AES-GCM,
    /// see [`CipherSuite::is_aes_gcm_hardware_accelerated`].
    AesGcm,
}

impl CipherSuite {
    /// Returns whether this CPU encrypts [`CipherSuite::AesGcm`] in hardware.
    ///
    /// The detection is cached by the standard library, making this cheap to call repeatedly.
    pub fn is_aes_gcm_hardware_accelerated() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            std::arch::is_x86_feature_detected!("aes")
                && std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("ssse3")
        }

        // The `aes` feature implies PMULL.
        #[cfg(target_arch = "aarch64")]
        {
            std::arch::is_aarch64_feature_detected!("aes")
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    }

    /// `HASH(protocol_name)`
    pub(crate) fn initial_chain_key(self) -> [u8; 32] {
        self.initial_state().chain_key
    }

    /// `HASH(initial_chain_key || prologue)`
    pub(crate) fn initial_chain_hash(self) -> [u8; 32] {
        self.initial_state().chain_hash
    }

    pub(crate) fn aead(self) -> &'static Algorithm {
        match self {
            CipherSuite::ChaChaPoly => &CHACHA20_POLY1305,
            CipherSuite::AesGcm => &AES_256_GCM,
        }
    }

    /// Encodes the AEAD nonce for the given counter.
    ///
    /// The Noise spec (section 12) prefixes the counter with 32 zero bits and encodes it
    /// little-endian for ChaChaPoly but big-endian for AESGCM.
    pub(crate) fn nonce(self, counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        match self {
            CipherSuite::ChaChaPoly => nonce[4..].copy_from_slice(&counter.to_le_bytes()),
            CipherSuite::AesGcm => nonce[4..].copy_from_slice(&counter.to_be_bytes()),
        }
        nonce
    }

    /// The number of messages after which a sending key should be replaced.
    pub(crate) fn rekey_after_messages(self) -> u64 {
        match self {
            CipherSuite::ChaChaPoly => u64::MAX,
            CipherSuite::AesGcm => AES_GCM_REKEY_AFTER_MESSAGES,
        }
    }

    /// The number of messages after which a sending key must no longer be used.
    pub(crate) fn reject_after_messages(self) -> u64 {
        match self {
            CipherSuite::ChaChaPoly => u64::MAX,
            CipherSuite::AesGcm => AES_GCM_REJECT_AFTER_MESSAGES,
        }
    }

    fn initial_state(self) -> &'static InitialState {
        match self {
            CipherSuite::ChaChaPoly => &CHACHA_POLY_INITIAL_STATE,
            CipherSuite::AesGcm => &AES_GCM_INITIAL_STATE,
        }
    }
}

const CHACHA_POLY_PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const AES_GCM_PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_AESGCM_BLAKE2s";
const WIREGUARD_PROLOGUE: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const AES_GCM_PROLOGUE: &[u8] = b"Firezone v1 AESGCM";

static CHACHA_POLY_INITIAL_STATE: LazyLock<InitialState> =
    LazyLock::new(|| InitialState::new(CHACHA_POLY_PROTOCOL_NAME, WIREGUARD_PROLOGUE));
static AES_GCM_INITIAL_STATE: LazyLock<InitialState> =
    LazyLock::new(|| InitialState::new(AES_GCM_PROTOCOL_NAME, AES_GCM_PROLOGUE));

struct InitialState {
    chain_key: [u8; 32],
    chain_hash: [u8; 32],
}

impl InitialState {
    fn new(protocol_name: &[u8], prologue: &[u8]) -> Self {
        let chain_key = b2s_hash(protocol_name, &[]);
        let chain_hash = b2s_hash(&chain_key, prologue);

        Self {
            chain_key,
            chain_hash,
        }
    }
}

/// Keeps the confidentiality advantage against AES-GCM below 2^-57 for messages of up to 2^7 blocks
/// (2 KiB), per draft-irtf-cfrg-aead-limits: `q <= (p^(1/2) * 2^(129/2) - 1) / (L + 1) ~= 2^29`.
///
/// This leaves a factor of two as margin.
const AES_GCM_REJECT_AFTER_MESSAGES: u64 = 1 << 28;
const AES_GCM_REKEY_AFTER_MESSAGES: u64 = AES_GCM_REJECT_AFTER_MESSAGES / 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_poly_initial_state_matches_wireguard() {
        let chain_key = CipherSuite::ChaChaPoly.initial_chain_key();
        let chain_hash = CipherSuite::ChaChaPoly.initial_chain_hash();

        assert_eq!(
            chain_key,
            [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ]
        );
        assert_eq!(
            chain_hash,
            [
                34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108,
                102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
            ]
        );
    }

    #[test]
    fn chacha_poly_nonce_is_little_endian() {
        let nonce = CipherSuite::ChaChaPoly.nonce(0x0102);

        assert_eq!(nonce, [0, 0, 0, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn aes_gcm_nonce_is_big_endian() {
        let nonce = CipherSuite::AesGcm.nonce(0x0102);

        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]);
    }
}
