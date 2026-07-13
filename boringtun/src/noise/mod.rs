// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

mod index;
mod session;
mod timers;

pub use index::Index;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

#[cfg(feature = "packet-queue")]
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

#[cfg(feature = "packet-queue")]
const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
///
/// We use a `u8` to align with the number of bits reserved in [`Index`] for the sessions.
const N_SESSIONS: u8 = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS as usize],
    /// Index of most recently used session
    current: Index,
    /// Queue to store blocked packets
    #[cfg(feature = "packet-queue")]
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    #[deprecated(note = "Prefer `Tunn::new_at` to avoid time-impurity")]
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        let now = Instant::now();
        Self::new_at(
            static_private,
            peer_static_public,
            preshared_key.map(x25519::StaticSecret::from),
            persistent_keepalive,
            Index::new_local(index),
            rate_limiter,
            rand::random(),
            now,
            now,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
    }

    /// Create a new tunnel using own private key and the peer public key
    #[expect(clippy::too_many_arguments, reason = "We don't care that much.")]
    pub fn new_at(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<x25519::StaticSecret>,
        persistent_keepalive: Option<u16>,
        index: Index,
        rate_limiter: Option<Arc<RateLimiter>>,
        rng_seed: u64,
        now: Instant,
        unix_instant: Instant,
        unix: Duration,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index,
                preshared_key,
                unix_instant,
                unix,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            #[cfg(feature = "packet-queue")]
            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none(), rng_seed, now),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new_at(
                    &static_public,
                    PEER_HANDSHAKE_RATE_LIMIT,
                    now,
                ))
            }),
        }
    }

    pub fn remote_static_public(&self) -> x25519::PublicKey {
        self.handshake.remote_static_public()
    }

    pub fn preshared_key(&self) -> &x25519::StaticSecret {
        self.handshake.preshared_key()
    }

    /// Update the private key and clear existing sessions
    #[deprecated(note = "Prefer `Tunn::set_static_private_at` to avoid time-impurity")]
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Result<(), WireGuardError> {
        self.set_static_private_at(static_private, static_public, rate_limiter, Instant::now());

        Ok(())
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private_at(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
        now: Instant,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new_at(
                &static_public,
                PEER_HANDSHAKE_RATE_LIMIT,
                now,
            ))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Set the `REKEY_ATTEMPT_TIME`.
    ///
    /// Defaults to 90s.
    pub fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.timers.set_rekey_attempt_time(rekey_attempt_time);
    }

    /// Set the `KEEPALIVE_TIMEOUT`.
    ///
    /// Defaults to 10s.
    pub fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.timers.set_keepalive_timeout(keepalive_timeout);
    }

    /// Set the `REKEY_TIMEOUT`, i.e. the interval at which an unanswered
    /// handshake initiation is retried.
    ///
    /// Defaults to 5s.
    pub fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.timers.set_rekey_timeout(rekey_timeout);
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    #[cfg(feature = "packet-queue")]
    #[deprecated(note = "Prefer `Tunn::encapsulate_at` to avoid time-impurity")]
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.encapsulate_at(src, dst, Instant::now())
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// On a packet for which there is no usable session yet, the packet is queued internally and a
    /// handshake is initiated. Requires the `packet-queue` feature; without it, use the
    /// side-effect-free [`Tunn::encapsulate_data_at`] and drive handshakes from the caller.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    #[cfg(feature = "packet-queue")]
    pub fn encapsulate_at<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnResult<'a> {
        match self.encapsulate_data_at(src, dst, now) {
            Ok(len) => TunnResult::WriteToNetwork(&mut dst[..len]),
            Err(WireGuardError::NoCurrentSession) => {
                // If there is no session, queue the packet for future retry
                self.queue_packet(src);
                // Initiate a new handshake if none is in progress
                self.format_handshake_initiation_at(dst, false, now)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Encapsulate a single packet from the tunnel interface **in place**, but only if
    /// there is currently a usable session.
    ///
    /// Returns `Ok(len)` when the encrypted WireGuard data message (`len` bytes) has been written
    /// to the start of `dst`. Returns `Err(WireGuardError::NoCurrentSession)` when there is no
    /// usable session; in that case `dst` is left untouched and - unlike [`Tunn::encapsulate_at`] -
    /// the packet is **not** queued and **no** handshake is initiated.
    pub fn encapsulate_data_at(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        now: Instant,
    ) -> Result<usize, WireGuardError> {
        let Some(session) = self.sessions[self.current]
            .as_ref()
            .filter(|s| s.should_use_at(now) || self.timers.is_responder())
        else {
            return Err(WireGuardError::NoCurrentSession);
        };

        // Send the packet using an established session
        let len = session.format_packet_data(src, dst)?.len();

        self.timer_tick(TimerName::TimeLastPacketSent, now);
        // Exclude Keepalive packets from timer update.
        if !src.is_empty() {
            self.timer_tick(TimerName::TimeLastDataPacketSent, now);
        }
        self.tx_bytes += src.len();

        Ok(len)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    #[deprecated(note = "Prefer `Tunn::decapsulate_at` to avoid time-impurity")]
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.decapsulate_at(src_addr, datagram, dst, Instant::now())
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate_at<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnResult<'a> {
        // A repeated call is signalled by an empty datagram and drains the next queued packet.
        // This only exists when the internal packet queue is compiled in.
        #[cfg(feature = "packet-queue")]
        if datagram.is_empty() {
            return self.send_queued_packet(dst, now);
        }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet_at(src_addr, datagram, &mut cookie, now)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst, now)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
        now: Instant,
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst, now),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst, now),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p, now),
            Packet::PacketData(p) => self.handle_data(p, dst, now),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let remote_idx = Index::from_peer(p.sender_idx);

        tracing::debug!(%remote_idx, "Received handshake_initiation",);

        let (packet, session) = self
            .handshake
            .receive_handshake_initialization(p, dst, now)?;

        // Store new session in ring buffer
        let local_idx = session.local_index();
        self.sessions[local_idx] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);
        self.timer_tick(TimerName::TimeLastPacketSent, now);
        self.timer_tick_session_established(false, now); // New session established, we are not the initiator

        tracing::debug!(%local_idx, %remote_idx, "Sending handshake_response");

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            local_idx = %Index::from_peer(p.receiver_idx),
            remote_idx = %Index::from_peer(p.sender_idx),
            "Received handshake_response"
        );

        let session = self.handshake.receive_handshake_response(p, now)?;

        let keepalive_packet = session.format_packet_data(&[], dst)?;
        // Store new session in ring buffer
        let local_idx = session.local_index();
        self.sessions[local_idx] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);
        self.timer_tick_session_established(true, now); // New session established, we are the initiator
        self.set_current_session(local_idx);

        tracing::debug!(%local_idx, "Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
        now: Instant,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let local_idx = Index::from_peer(p.receiver_idx);

        tracing::debug!(%local_idx, "Received cookie_reply");

        self.handshake.receive_cookie_reply(p, now)?;
        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        tracing::debug!(%local_idx, "Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: Index) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }

        let Some(new) = self.sessions[new_idx].as_ref() else {
            debug_assert!(false, "new session should always exist");
            return;
        };
        if self.sessions[cur_idx]
            .as_ref()
            .is_some_and(|current| current.established_at() > new.established_at())
        {
            // The current session is "newer" than the new one, don't update.
            return;
        }

        self.current = new_idx;
        tracing::debug!(idx = %new_idx, "New session");
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
        now: Instant,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let remote_idx = Index::from_peer(packet.receiver_idx);

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[remote_idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(%remote_idx, "No current session available");
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(remote_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived, now);

        Ok(self.validate_decapsulated_packet(decapsulated_packet, now))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    #[deprecated(note = "Prefer `Tunn::format_handshake_initiation_at` to avoid time-impurity")]
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        self.format_handshake_initiation_at(dst, force_resend, Instant::now())
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation_at<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
        now: Instant,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear(now);
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.format_handshake_initiation(dst, now) {
            Ok((packet, local_idx)) => {
                tracing::debug!(%local_idx, "Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted, now);
                }
                self.timer_tick(TimerName::TimeLastPacketSent, now);
                TunnResult::WriteToNetwork(packet)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        now: Instant,
    ) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived, now);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    #[cfg(feature = "packet-queue")]
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8], now: Instant) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate_at(&packet, dst, now) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    #[cfg(feature = "packet-queue")]
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    #[cfg(feature = "packet-queue")]
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    #[cfg(feature = "packet-queue")]
    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[session_idx.wrapping_sub(i)] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    #[deprecated(note = "Prefer `Tunn::stats_at` to avoid time-impurity")]
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.stats_at(Instant::now())
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats_at(&self, now: Instant) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake_at(now);
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}
