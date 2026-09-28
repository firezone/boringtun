use ring::aead::{Algorithm, AES_256_GCM, CHACHA20_POLY1305};

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
        match self {
            CipherSuite::ChaChaPoly => [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ],
            CipherSuite::AesGcm => [
                239, 203, 191, 167, 13, 128, 238, 35, 220, 247, 237, 244, 63, 185, 136, 222, 109,
                234, 136, 254, 37, 254, 172, 56, 81, 187, 75, 43, 13, 9, 211, 178,
            ],
        }
    }

    /// `HASH(initial_chain_key || IDENTIFIER)`
    pub(crate) fn initial_chain_hash(self) -> [u8; 32] {
        match self {
            CipherSuite::ChaChaPoly => [
                34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108,
                102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
            ],
            CipherSuite::AesGcm => [
                234, 53, 188, 1, 149, 21, 240, 59, 157, 13, 110, 10, 205, 252, 66, 86, 33, 185,
                208, 88, 53, 59, 152, 5, 203, 244, 150, 99, 176, 201, 69, 48,
            ],
        }
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
