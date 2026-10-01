// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{
    index::Index,
    timers::{REJECT_AFTER_TIME, SHOULD_NOT_USE_AFTER_TIME},
    PacketData,
};
use crate::noise::errors::WireGuardError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::sync::Arc;
use std::time::Instant;

pub struct Session {
    established_at: Instant,
    pub(crate) receiving_index: Index,
    sending_index: Index,
    receiver: Arc<LessSafeKey>,
    sender: Arc<LessSafeKey>,
    sending_key_counter: u64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 128; // Suffice to reorder 128*16 = 8192 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        Self {
            next: Default::default(),
            receive_cnt: Default::default(),
            bitmap: [0; _],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::DuplicateCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: Index,
        peer_index: Index,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
        now: Instant,
    ) -> Session {
        Session {
            established_at: now,
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: Arc::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            )),
            sender: Arc::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap(),
            )),
            sending_key_counter: 0,
            receiving_key_counter: Default::default(),
        }
    }

    pub(super) fn local_index(&self) -> Index {
        self.receiving_index
    }

    pub(crate) fn established_at(&self) -> Instant {
        self.established_at
    }

    pub(crate) fn expired_at(&self, time: Instant) -> bool {
        time >= self.established_at + REJECT_AFTER_TIME
    }

    pub(crate) fn should_use_at(&self, time: Instant) -> bool {
        time <= self.established_at + SHOULD_NOT_USE_AFTER_TIME
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        self.receiving_key_counter.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&mut self, counter: u64) -> Result<(), WireGuardError> {
        let ret = self.receiving_key_counter.mark_did_receive(counter);
        if ret.is_ok() {
            self.receiving_key_counter.receive_cnt += 1;
        }
        ret
    }

    /// Assigns the next counter to a data message, deferring writing and encrypting it.
    pub(super) fn prepare_packet_data(&mut self) -> PendingSeal {
        let counter = self.sending_key_counter;
        self.sending_key_counter += 1;

        PendingSeal {
            key: Arc::clone(&self.sender),
            receiver_index: self.sending_index,
            counter,
        }
    }

    /// Checks the counter of a data message, deferring its decryption.
    pub(super) fn prepare_receive_packet_data(
        &self,
        packet: PacketData,
    ) -> Result<PendingOpen, WireGuardError> {
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(packet.counter)?;

        Ok(PendingOpen {
            key: Arc::clone(&self.receiver),
            receiving_index: self.receiving_index,
            counter: packet.counter,
        })
    }

    /// Accepts the counter of a decrypted data message, returning the length of its plaintext.
    pub(super) fn finish_receive_packet_data(
        &mut self,
        opened: Opened,
    ) -> Result<usize, WireGuardError> {
        debug_assert_eq!(opened.receiving_index, self.receiving_index);

        let plaintext_len = opened.plaintext_len?;

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(opened.counter)?;

        Ok(plaintext_len)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        (
            self.receiving_key_counter.next,
            self.receiving_key_counter.receive_cnt,
        )
    }
}

/// The encryption of a data message whose counter is already assigned.
///
/// The nonce is fixed when the [`PendingSeal`] is created, so seals may run in any order and on
/// any thread: the receiver's sliding replay window accepts data messages that arrive out of order.
#[must_use = "the data message is not sent until it is sealed"]
pub struct PendingSeal {
    key: Arc<LessSafeKey>,
    receiver_index: Index,
    counter: u64,
}

impl PendingSeal {
    /// Writes the data message encrypting `plaintext` to the start of `dst` and returns its length.
    ///
    /// The data message is 32 bytes longer than `plaintext`.
    ///
    /// # Panics
    ///
    /// Panics if `dst` is shorter than the data message.
    pub fn seal_into(self, plaintext: &[u8], dst: &mut [u8]) -> usize {
        let len = DATA_OFFSET + plaintext.len() + AEAD_SIZE;

        let (header, rest) = dst[..len].split_at_mut(DATA_OFFSET);
        let (data, tag) = rest.split_at_mut(plaintext.len());

        let (message_type, rest) = header.split_at_mut(4);
        let (receiver_index, counter) = rest.split_at_mut(4);
        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.receiver_index.to_le_bytes());
        counter.copy_from_slice(&self.counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        data.copy_from_slice(plaintext);

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        let computed_tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), data)
            .expect("plaintext of a data message is always within the AEAD's limits");
        tag.copy_from_slice(computed_tag.as_ref());

        len
    }
}

/// The decryption of a data message whose counter has been checked.
///
/// Its counter has passed the replay check but is not yet marked as received: that only happens
/// once the decrypted message is handed back to the [`Tunn`](super::Tunn), so a message that fails
/// to authenticate never advances the replay window.
#[must_use = "the data message is not decrypted until it is opened"]
pub struct PendingOpen {
    key: Arc<LessSafeKey>,
    receiving_index: Index,
    counter: u64,
}

impl PendingOpen {
    /// Copies `ciphertext` to the start of `dst` and decrypts it in place.
    ///
    /// `ciphertext` is the encrypted part of the data message this [`PendingOpen`] was
    /// prepared from; anything else fails to authenticate.
    pub fn open_into(self, ciphertext: &[u8], dst: &mut [u8]) -> Opened {
        let plaintext_len = self.decrypt(ciphertext, dst);

        Opened {
            receiving_index: self.receiving_index,
            counter: self.counter,
            plaintext_len,
        }
    }

    fn decrypt(&self, ciphertext: &[u8], dst: &mut [u8]) -> Result<usize, WireGuardError> {
        let ct_len = ciphertext.len();
        let buf_len = dst.len();

        let Some(buf) = dst.get_mut(..ct_len) else {
            tracing::warn!(%buf_len, %ct_len, "Destination buffer too small for incoming packet data");

            return Err(WireGuardError::DestinationBufferTooSmall);
        };
        buf.copy_from_slice(ciphertext);

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        let plaintext = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), buf)
            .map_err(|_| WireGuardError::InvalidAeadTag)?;

        Ok(plaintext.len())
    }
}

/// A data message decrypted by [`PendingOpen::open_into`], to be handed back to the [`Tunn`](super::Tunn).
#[must_use = "the data message is not accepted until it is handed back to the `Tunn`"]
pub struct Opened {
    pub(super) receiving_index: Index,
    counter: u64,
    plaintext_len: Result<usize, WireGuardError>,
}
