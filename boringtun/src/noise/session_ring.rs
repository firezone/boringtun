// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Default data-path AEAD backend, built on `ring`.
//!
//! `ring` only exposes in-place AEAD, so each packet is copied into the destination buffer and then
//! sealed/opened in place. This mirrors the historical behavior of `Session`.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

const AEAD_SIZE: usize = 16;

pub(super) struct Sealer(LessSafeKey);
pub(super) struct Opener(LessSafeKey);

impl Sealer {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap(),
        ))
    }

    /// Seals `plaintext` into `out`, where `out.len() == plaintext.len() + AEAD_SIZE`.
    ///
    /// Writes the ciphertext to `out[..plaintext.len()]` and the tag to the trailing 16 bytes.
    pub(super) fn seal(&self, nonce: [u8; 12], plaintext: &[u8], out: &mut [u8]) {
        let n = plaintext.len();

        // `ring` is in-place only, so copy the plaintext in first, then seal it in place.
        out[..n].copy_from_slice(plaintext);
        let tag = self
            .0
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut out[..n],
            )
            .expect("encryption is infallible");
        out[n..n + AEAD_SIZE].copy_from_slice(tag.as_ref());
    }
}

impl Opener {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap(),
        ))
    }

    /// Opens `ciphertext_and_tag` (ciphertext followed by the 16-byte tag) into `out`, which must be
    /// at least `ciphertext_and_tag.len()` bytes. Returns the plaintext length on success.
    pub(super) fn open(
        &self,
        nonce: [u8; 12],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ()> {
        let ct_len = ciphertext_and_tag.len();

        // `ring` is in-place only, so copy the ciphertext+tag in first, then open it in place.
        out[..ct_len].copy_from_slice(ciphertext_and_tag);
        let plaintext = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut out[..ct_len],
            )
            .map_err(|_| ())?;

        Ok(plaintext.len())
    }
}
