// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Out-of-place data-path AEAD backend, built directly on AWS-LC (`aws-lc-sys`).
//!
//! ChaCha20-Poly1305 is a stream cipher, so the payload can be encrypted/decrypted straight from the
//! source buffer into the destination buffer instead of copying it first and operating in place.
//!
//! AWS-LC's scatter/gather AEAD supports this:
//! * `EVP_AEAD_CTX_seal_scatter` encrypts `in` into a separate `out` and writes the tag to `out_tag`.
//! * `EVP_AEAD_CTX_open_gather` decrypts a separate ciphertext + tag into `out`.
//!
//! We call these via `aws-lc-sys` because the safe `aws-lc-rs` wrapper only exposes the out-of-place
//! *seal* through its `extra_in` path, which routes the bulk payload through a slow, non-vectorized
//! code path. `open_gather` is fast in the safe wrapper, but we use the raw API for both directions
//! so a single `EVP_AEAD_CTX` abstraction serves the sealer and the opener.

use aws_lc_sys::{
    EVP_AEAD_CTX_free, EVP_AEAD_CTX_new, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal_scatter,
    EVP_aead_chacha20_poly1305, EVP_AEAD_CTX,
};
use core::ptr::{self, NonNull};

const AEAD_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

/// Owned, key-scheduled `EVP_AEAD_CTX` for ChaCha20-Poly1305.
struct Ctx(NonNull<EVP_AEAD_CTX>);

// SAFETY: An `EVP_AEAD_CTX` is immutable once created; `EVP_AEAD_CTX_seal_scatter` and
// `EVP_AEAD_CTX_open_gather` take it by `const` pointer and do not mutate it, so it can be shared
// across threads. (`aws-lc-rs`'s `LessSafeKey` is `Send + Sync` for the same reason.)
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    fn new(key: [u8; 32]) -> Self {
        // SAFETY: `EVP_aead_chacha20_poly1305()` returns a pointer to a static AEAD descriptor.
        // `key` points to exactly 32 bytes, which is the required key length for this AEAD, and the
        // 16-byte tag length is valid. `EVP_AEAD_CTX_new` copies the key into the returned context.
        let ctx = unsafe {
            EVP_AEAD_CTX_new(
                EVP_aead_chacha20_poly1305(),
                key.as_ptr(),
                key.len(),
                AEAD_SIZE,
            )
        };

        Self(NonNull::new(ctx).expect("EVP_AEAD_CTX_new failed to allocate"))
    }

    fn as_ptr(&self) -> *const EVP_AEAD_CTX {
        self.0.as_ptr()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `EVP_AEAD_CTX_new` and is freed exactly once here.
        unsafe { EVP_AEAD_CTX_free(self.0.as_ptr()) }
    }
}

pub(super) struct Sealer(Ctx);
pub(super) struct Opener(Ctx);

impl Sealer {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self(Ctx::new(key))
    }

    /// Seals `plaintext` into `out`, where `out.len() == plaintext.len() + AEAD_SIZE`.
    ///
    /// Encrypts straight from `plaintext` into `out[..plaintext.len()]` (out-of-place; the buffers
    /// are disjoint) and writes the tag to the trailing 16 bytes.
    pub(super) fn seal(&self, nonce: [u8; NONCE_SIZE], plaintext: &[u8], out: &mut [u8]) {
        let n = plaintext.len();
        debug_assert_eq!(out.len(), n + AEAD_SIZE);

        let (ciphertext, tag) = out.split_at_mut(n);
        let mut out_tag_len = 0usize;

        // SAFETY: `ciphertext` is valid for `n` writes and `tag` for `AEAD_SIZE` writes; `plaintext`
        // is valid for `n` reads and is a distinct allocation from `out`, satisfying the
        // non-overlap requirement of `seal_scatter`. `nonce` is 12 bytes. There is no extra input
        // and no associated data. The return value is checked.
        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                self.0.as_ptr(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut out_tag_len,
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                n,
                ptr::null(),
                0,
                ptr::null(),
                0,
            )
        };

        assert_eq!(rc, 1, "EVP_AEAD_CTX_seal_scatter failed");
        debug_assert_eq!(out_tag_len, AEAD_SIZE);
    }
}

impl Opener {
    pub(super) fn new(key: [u8; 32]) -> Self {
        Self(Ctx::new(key))
    }

    /// Opens `ciphertext_and_tag` (ciphertext followed by the 16-byte tag) into `out`, which must be
    /// at least `ciphertext_and_tag.len() - AEAD_SIZE` bytes. Returns the plaintext length on
    /// success. On failure `out` may hold unverified plaintext and must not be used by the caller.
    pub(super) fn open(
        &self,
        nonce: [u8; NONCE_SIZE],
        ciphertext_and_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ()> {
        let total = ciphertext_and_tag.len();
        if total < AEAD_SIZE {
            return Err(());
        }
        let n = total - AEAD_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(n);
        debug_assert!(out.len() >= n);

        // SAFETY: `out` is valid for `n` writes (asserted above); `ciphertext`/`tag` are valid for
        // their respective reads and are a distinct allocation from `out`. `nonce` is 12 bytes and
        // `tag` is 16 bytes. There is no associated data. The return value is checked, and on
        // failure we report an error without exposing `out`.
        let rc = unsafe {
            EVP_AEAD_CTX_open_gather(
                self.0.as_ptr(),
                out.as_mut_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                ciphertext.as_ptr(),
                n,
                tag.as_ptr(),
                tag.len(),
                ptr::null(),
                0,
            )
        };

        if rc != 1 {
            return Err(());
        }

        Ok(n)
    }
}
