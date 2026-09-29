//! Interoperability with `snow`, an independent Noise implementation that is
//! itself checked against the published cacophony test vectors.
//!
//! WireGuard is `Noise_IKpsk2` with its identifier as prologue, framed with
//! message types, indices and MACs. `snow` plays the initiator; we add the
//! WireGuard framing around its messages and let a [`Tunn`] respond.

use std::time::{Duration, Instant};

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use boringtun::noise::{CipherSuite, Index, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use typenum::U16;

use crate::harness::ipv4_packet;

const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

#[test]
fn chacha_poly_interoperates_with_snow() {
    interoperate_with_snow(
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
        CipherSuite::ChaChaPoly,
    );
}

#[test]
fn aes_gcm_interoperates_with_snow() {
    interoperate_with_snow("Noise_IKpsk2_25519_AESGCM_BLAKE2s", CipherSuite::AesGcm);
}

fn interoperate_with_snow(protocol_name: &str, cipher_suite: CipherSuite) {
    let now = Instant::now();
    let initiator_secret = StaticSecret::random();
    let responder_secret = StaticSecret::random();
    let responder_public = PublicKey::from(&responder_secret);
    let psk = [0x42; 32];

    let mut responder = Tunn::new_at(
        responder_secret,
        PublicKey::from(&initiator_secret),
        Some(StaticSecret::from(psk)),
        cipher_suite,
        None,
        Index::new_local(2),
        None,
        0,
        now,
        now,
        Duration::from_secs(1_700_000_000),
    );
    let mut initiator = snow::Builder::new(protocol_name.parse().unwrap())
        .local_private_key(&initiator_secret.to_bytes())
        .unwrap()
        .remote_public_key(responder_public.as_bytes())
        .unwrap()
        .psk(2, &psk)
        .unwrap()
        .prologue(IDENTIFIER)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut buf = [0u8; 2048];
    let mut noise = [0u8; 2048];

    let tai64n_timestamp = [0x40, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let len = initiator
        .write_message(&tai64n_timestamp, &mut noise)
        .unwrap();
    let init = handshake_initiation(&noise[..len], &responder_public);
    let TunnResult::WriteToNetwork(response) = responder.decapsulate_at(None, &init, &mut buf, now)
    else {
        panic!("responder rejected the handshake initiation");
    };
    let responder_index = u32::from_le_bytes(response[4..8].try_into().unwrap());
    let payload_len = initiator
        .read_message(&response[12..60], &mut noise)
        .expect("snow to accept the handshake response");
    assert_eq!(payload_len, 0);
    let transport = initiator.into_stateless_transport_mode().unwrap();

    // Counter 1 tells the nonce encodings apart; counter 0 does not.
    for counter in [0, 1] {
        let ip_packet = ipv4_packet(format!("to responder #{counter}").as_bytes());
        let len = transport
            .write_message(counter, &ip_packet, &mut noise)
            .unwrap();
        let datagram = data_message(responder_index, counter, &noise[..len]);

        let TunnResult::WriteToTunnelV4(received, _) =
            responder.decapsulate_at(None, &datagram, &mut buf, now)
        else {
            panic!("responder failed to decrypt data packet #{counter}");
        };
        assert_eq!(received, ip_packet.as_slice());
    }

    for counter in [0, 1] {
        let ip_packet = ipv4_packet(format!("to initiator #{counter}").as_bytes());
        let len = responder
            .encapsulate_data_at(&ip_packet, &mut buf, now)
            .unwrap();
        let datagram = &buf[..len];
        assert_eq!(datagram[8..16], u64::to_le_bytes(counter));

        let len = transport
            .read_message(counter, &datagram[16..], &mut noise)
            .expect("snow to decrypt the data packet");
        assert_eq!(&noise[..len], ip_packet.as_slice());
    }
}

/// Frames the Noise message as a WireGuard handshake initiation from sender index 1.
fn handshake_initiation(noise_message: &[u8], responder_public: &PublicKey) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.extend_from_slice(noise_message);

    let mac1_key = Blake2s256::new()
        .chain_update(LABEL_MAC1)
        .chain_update(responder_public.as_bytes())
        .finalize();
    let mut mac1 = Blake2sMac::<U16>::new_from_slice(&mac1_key).unwrap();
    mac1.update(&packet);
    packet.extend_from_slice(&mac1.finalize_fixed());
    packet.extend_from_slice(&[0; 16]); // mac2: no cookie

    packet
}

fn data_message(receiver_index: u32, counter: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&4u32.to_le_bytes());
    packet.extend_from_slice(&receiver_index.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(ciphertext);

    packet
}
