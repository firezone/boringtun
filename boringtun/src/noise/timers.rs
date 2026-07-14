// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
use std::iter;
use std::ops::{Index, IndexMut};

use rand::RngExt;
use rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, Instant};

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
pub(crate) const MAX_JITTER: Duration = Duration::from_millis(333);

/// Time-period after which a session should no longer be used for new packets.
///
/// In order for [`REKEY_AFTER_TIME`] to take effect, at least one data packet needs to be sent on a session.
/// If this data packet is sent close to the expire of the session ([`REJECT_AFTER_TIME`]), the session
/// may be expired by the time the packet reaches the receiver (and thus will not be able to be decrypted).
///
/// To avoid this, we stop using the session after [`REJECT_AFTER_TIME`] - [`KEEPALIVE_TIMEOUT`].
pub(crate) const SHOULD_NOT_USE_AFTER_TIME: Duration =
    Duration::from_secs(REJECT_AFTER_TIME.as_secs() - KEEPALIVE_TIMEOUT.as_secs());

#[derive(Debug)]
pub enum TimerName {
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    /// Time we last updated our timers
    TimeLastUpdate,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    timers: [Instant; TimerName::Top as usize],
    /// The last data packet we received without having sent a reply since.
    ///
    /// If `Some`, the passive-keepalive deadline is derived from it on demand.
    last_data_received_without_reply: Option<Instant>,
    /// The first data packet we sent without having heard back since.
    ///
    /// If `Some`, the new-handshake deadline is derived from it on demand.
    first_data_sent_without_reply: Option<Instant>,
    persistent_keepalive: usize,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
    /// When we should sent a scheduled handshake.
    send_handshake_at: Option<Instant>,

    jitter_rng: StdRng,

    rekey_attempt_time: Duration,
    keepalive_timeout: Duration,
    rekey_timeout: Duration,
}

impl Timers {
    pub(super) fn new(
        persistent_keepalive: Option<u16>,
        reset_rr: bool,
        rng_seed: u64,
        now: Instant,
    ) -> Timers {
        Timers {
            is_initiator: false,
            timers: [now; TimerName::Top as usize],
            last_data_received_without_reply: Default::default(),
            first_data_sent_without_reply: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            should_reset_rr: reset_rr,
            send_handshake_at: None,
            jitter_rng: StdRng::seed_from_u64(rng_seed),
            rekey_attempt_time: REKEY_ATTEMPT_TIME,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            rekey_timeout: REKEY_TIMEOUT,
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub(crate) fn is_responder(&self) -> bool {
        !self.is_initiator()
    }

    /// After `REJECT_AFTER_TIME * 3` without a new handshake, all ephemeral and
    /// symmetric key material is wiped and the connection is considered dead.
    pub(crate) fn reject_after_time(&self) -> Instant {
        self[TimeSessionEstablished] + REJECT_AFTER_TIME * 3
    }

    /// After `REKEY_ATTEMPT_TIME` of unsuccessfully trying to complete a
    /// handshake, we give up.
    pub(crate) fn rekey_attempt_time(&self) -> Instant {
        self[TimeLastHandshakeStarted] + self.rekey_attempt_time
    }

    /// As the initiator, we start a new handshake `REKEY_AFTER_TIME` after
    /// establishing a session on which we have since sent data.
    pub(crate) fn rekey_after_time_on_send(&self) -> Option<Instant> {
        if !self.is_initiator {
            // If we aren't the initiator of the current session, this timer does not matter.
            return None;
        }

        let session_established = self[TimeSessionEstablished];

        if session_established >= self[TimeLastDataPacketSent] {
            // If we haven't sent any data yet, this timer doesn't matter.
            return None;
        }

        Some(session_established + REKEY_AFTER_TIME)
    }

    /// As the initiator, we start a new handshake once a session on which we
    /// have since received data gets close to its expiry.
    pub(crate) fn reject_after_time_on_receive(&self) -> Option<Instant> {
        if !self.is_initiator {
            // If we aren't the initiator of the current session, this timer does not matter.
            return None;
        }

        let session_established = self[TimeSessionEstablished];

        if session_established >= self[TimeLastDataPacketReceived] {
            // If we haven't received any data yet, this timer doesn't matter.
            return None;
        }

        Some(session_established + REJECT_AFTER_TIME - self.keepalive_timeout - self.rekey_timeout)
    }

    /// If we sent data but have not heard back within `KEEPALIVE_TIMEOUT +
    /// REKEY_TIMEOUT`, we assume the session is dead and start a new handshake.
    pub(crate) fn rekey_after_time_without_response(&self) -> Option<Instant> {
        let first_packet_without_reply = self.first_data_sent_without_reply?;

        Some(first_packet_without_reply + self.keepalive_timeout + self.rekey_timeout)
    }

    /// If we received data but have not sent anything back within
    /// `KEEPALIVE_TIMEOUT`, we send a passive keepalive.
    pub(crate) fn keepalive_after_time_without_send(&self) -> Option<Instant> {
        let last_data_received_without_reply = self.last_data_received_without_reply?;

        Some(last_data_received_without_reply + self.keepalive_timeout)
    }

    /// If configured, we send a keepalive every `persistent_keepalive` seconds.
    pub(crate) fn next_persistent_keepalive(&self) -> Option<Instant> {
        let keepalive = Duration::from_secs(self.persistent_keepalive as u64);

        if keepalive.is_zero() {
            return None;
        }

        Some(self[TimePersistentKeepalive] + keepalive)
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self, now: Instant) {
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.first_data_sent_without_reply = None;
        self.last_data_received_without_reply = None;
    }

    pub(crate) fn set_rekey_attempt_time(&mut self, rekey_attempt_time: Duration) {
        self.rekey_attempt_time = rekey_attempt_time;
    }

    pub(crate) fn set_keepalive_timeout(&mut self, keepalive_timeout: Duration) {
        self.keepalive_timeout = keepalive_timeout;
    }

    pub(crate) fn set_rekey_timeout(&mut self, rekey_timeout: Duration) {
        self.rekey_timeout = rekey_timeout;
    }
}

impl Index<TimerName> for Timers {
    type Output = Instant;
    fn index(&self, index: TimerName) -> &Self::Output {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Self::Output {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName, now: Instant) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.first_data_sent_without_reply = None;
            }
            TimeLastPacketSent => {
                self.timers.last_data_received_without_reply = None;
            }
            TimeLastDataPacketReceived => {
                self.timers.last_data_received_without_reply = Some(now);
            }
            TimeLastDataPacketSent => {
                match self.timers.first_data_sent_without_reply {
                    Some(_) => {
                        // This isn't the first timer tick (i.e. not the first packet)
                        // we haven't received a response to.
                    }
                    None => {
                        // We sent a packet and haven't heard back yet.
                        // Remember when, so we can derive the new-handshake deadline.
                        self.timers.first_data_sent_without_reply = Some(now)
                    }
                }
            }
            _ => {}
        }

        self.timers[timer_name] = now;
    }

    pub(super) fn timer_tick_session_established(&mut self, is_initiator: bool, now: Instant) {
        self.timer_tick(TimeSessionEstablished, now);
        self.timers.is_initiator = is_initiator;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self, now: Instant) {
        for session in &mut self.sessions {
            *session = None;
        }

        #[cfg(feature = "packet-queue")]
        self.packet_queue.clear();

        self.timers.clear(now);
    }

    fn expire_sessions(&mut self, now: Instant) {
        for maybe_session in self.sessions.iter_mut() {
            let Some(session) = maybe_session else {
                continue;
            };

            let is_current = self.current == session.local_index();

            if session.expired_at(now) {
                tracing::debug!(
                    session = %session.receiving_index,
                    %is_current,
                    "SESSION_EXPIRED(REJECT_AFTER_TIME)"
                );
                *maybe_session = None;
            }
        }
    }

    /// The earliest [`Instant`] at which one of our sessions expires.
    fn next_expired_session(&self) -> Option<Instant> {
        self.sessions
            .iter()
            .flatten()
            .map(|s| s.established_at() + REJECT_AFTER_TIME)
            .min()
    }

    /// The [`Instant`] at which we need to retransmit our handshake initiation,
    /// together with the local index of the in-flight handshake.
    ///
    /// Returns `None` unless we are currently the initiator of an in-progress
    /// handshake.
    fn handshake_rekey_timeout(&self) -> Option<(Instant, super::Index)> {
        let (time_sent, local_index) = self.handshake.timer()?;

        Some((time_sent + self.timers.rekey_timeout, local_index))
    }

    #[deprecated(note = "Prefer `Timers::update_timers_at` to avoid time-impurity")]
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.update_timers_at(dst, Instant::now())
    }

    pub fn update_timers_at<'a>(&mut self, dst: &'a mut [u8], now: Instant) -> TunnResult<'a> {
        self.timers[TimeLastUpdate] = now;

        if let Some(scheduled_handshake_at) = self.timers.send_handshake_at {
            // If we have scheduled a handshake and the deadline expired, send it immediately.
            if now >= scheduled_handshake_at {
                self.timers.send_handshake_at = None;
                return self.format_handshake_initiation_at(dst, true, now);
            }

            debug_assert!(
                scheduled_handshake_at
                    .checked_duration_since(now)
                    .is_some_and(|remaining| remaining <= MAX_JITTER),
                "Should never suspend for longer than jitter duration"
            );

            // We have a handshake scheduled but the deadline is not expired yet.
            // Don't do anything to avoid repeated printing of logs.
            // The below logic would still evaluate that we need to send another handshake.
            return TunnResult::Done;
        }

        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count_at(now);
        }

        self.expire_sessions(now);

        // In case our session expired, create a new one iff we initiated the previous one.
        if self.sessions[self.current].is_none()
            && !self.handshake.is_in_progress()
            && self.timers.is_initiator()
        {
            handshake_initiation_required = true;
        }

        if self.handshake.is_expired() {
            return TunnResult::Err(WireGuardError::ConnectionExpired);
        }

        // Clear cookie after COOKIE_EXPIRATION_TIME
        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            tracing::debug!("COOKIE_EXPIRED");
            self.handshake.clear_cookie();
        }

        // All ephemeral private keys and symmetric session keys are zeroed out after
        // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
        if now >= self.timers.reject_after_time() {
            tracing::debug!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
            self.handshake.set_expired();
            self.clear_all(now);
            return TunnResult::Err(WireGuardError::ConnectionExpired);
        }

        if let Some((rekey_timeout, local_idx)) = self.handshake_rekey_timeout() {
            // Handshake Initiation Retransmission
            if now >= self.timers.rekey_attempt_time() {
                // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                // the retries give up and cease, and clear all existing packets queued
                // up to be sent. If a packet is explicitly queued up to be sent, then
                // this timer is reset.
                tracing::debug!(%local_idx, "CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                self.handshake.set_expired();
                self.clear_all(now);
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if now >= rekey_timeout {
                // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                // if a response has not been received, where jitter is some random
                // value between 0 and 333 ms (`MAX_JITTER`).
                tracing::debug!(%local_idx, "HANDSHAKE(REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }
        } else {
            // After sending a packet, if the sender was the original initiator
            // of the handshake and if the current session key is REKEY_AFTER_TIME
            // ms old, we initiate a new handshake. If the sender was the original
            // responder of the handshake, it does not re-initiate a new handshake
            // after REKEY_AFTER_TIME ms like the original initiator does.
            if self
                .timers
                .rekey_after_time_on_send()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                handshake_initiation_required = true;
            }

            // After receiving a packet, if the receiver was the original initiator
            // of the handshake and if the current session key is REJECT_AFTER_TIME
            // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
            // handshake.
            if self
                .timers
                .reject_after_time_on_receive()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!(
                    "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (on receive))"
                );
                handshake_initiation_required = true;
            }

            // If we have sent a packet to a given peer but have not received a
            // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
            // we initiate a new handshake.
            if self
                .timers
                .rekey_after_time_without_response()
                .is_some_and(|deadline| now >= deadline)
            {
                tracing::debug!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }

            if !handshake_initiation_required {
                // If a packet has been received from a given peer, but we have not sent one back
                // to the given peer in KEEPALIVE ms, we send an empty packet.
                if self
                    .timers
                    .keepalive_after_time_without_send()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                    keepalive_required = true;
                }

                // Persistent KEEPALIVE
                if self
                    .timers
                    .next_persistent_keepalive()
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                    self.timer_tick(TimePersistentKeepalive, now);
                    keepalive_required = true;
                }
            }
        }

        if handshake_initiation_required {
            let jitter = self
                .timers
                .jitter_rng
                .random_range(Duration::ZERO..=MAX_JITTER);

            let existing = self.timers.send_handshake_at.replace(now + jitter);
            debug_assert!(
                existing.is_none(),
                "Should never override existing handshake"
            );

            tracing::debug!(?jitter, "Scheduling new handshake");

            return TunnResult::Done;
        }

        if keepalive_required {
            // A keepalive is only ever sent on an established session, so encrypt the empty packet
            // in place; there is no need to queue it or start a handshake.
            return match self.encapsulate_data_at(&[], dst, now) {
                Ok(len) => TunnResult::WriteToNetwork(&mut dst[..len]),
                Err(WireGuardError::NoCurrentSession) => TunnResult::Done,
                Err(e) => TunnResult::Err(e),
            };
        }

        TunnResult::Done
    }

    /// Returns the [`Instant`] at which [`Tunn::update_timers_at`] next needs to
    /// be called, together with a human-readable reason for debugging.
    ///
    /// Calling it earlier than the given [`Instant`] is safe but unlikely to
    /// have any effect. Driving the state machine by repeatedly polling at the
    /// returned [`Instant`] is sufficient: there is no need to call
    /// [`Tunn::update_timers_at`] on a fixed interval.
    pub fn next_timer_update(&self) -> Option<(Instant, &'static str)> {
        let (next, reason) = self.next_timer_update_internal()?;
        let last_update = self.timers[TimeLastUpdate];

        // Never announce an [`Instant`] in the past: a deadline may already have
        // elapsed by the time the caller polls us.
        Some((next.max(last_update), reason))
    }

    fn next_timer_update_internal(&self) -> Option<(Instant, &'static str)> {
        // Mimic `update_timers_at`: if we have a handshake scheduled, no other timer matters.
        if let Some(scheduled_handshake) = self.timers.send_handshake_at {
            return Some((scheduled_handshake, "scheduled handshake"));
        }

        let common_timers = iter::empty()
            .chain(
                self.next_expired_session()
                    .map(|instant| (instant, "next expired session")),
            )
            .chain(
                self.handshake
                    .cookie_expiration()
                    .map(|instant| (instant, "cookie expiration")),
            )
            .chain(iter::once((
                self.timers.reject_after_time(),
                "reject-after-time",
            )));

        if let Some((rekey_timeout, _)) = self.handshake_rekey_timeout() {
            // While a handshake is in progress, only the handshake timers matter.
            common_timers
                .chain(iter::once((rekey_timeout, "rekey-timeout")))
                .chain(iter::once((
                    self.timers.rekey_attempt_time(),
                    "rekey-attempt",
                )))
                .min_by_key(|(instant, _)| *instant)
        } else {
            // Persistent keep-alive only makes sense if the current session is active.
            let persistent_keepalive = self.sessions[self.current]
                .as_ref()
                .and_then(|_| self.timers.next_persistent_keepalive());

            common_timers
                .chain(
                    self.timers
                        .rekey_after_time_on_send()
                        .map(|instant| (instant, "rekey-after-time (on send)")),
                )
                .chain(
                    self.timers
                        .reject_after_time_on_receive()
                        .map(|instant| (instant, "reject-after-time (on receive)")),
                )
                .chain(
                    self.timers
                        .rekey_after_time_without_response()
                        .map(|instant| (instant, "rekey-after-time (without response)")),
                )
                .chain(
                    self.timers
                        .keepalive_after_time_without_send()
                        .map(|instant| (instant, "keepalive-after-time (without send)")),
                )
                .chain(persistent_keepalive.map(|instant| (instant, "persistent keep-alive")))
                .min_by_key(|(instant, _)| *instant)
        }
    }

    #[deprecated(note = "Prefer `Tunn::time_since_last_handshake_at` to avoid time-impurity")]
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.time_since_last_handshake_at(Instant::now())
    }

    pub fn time_since_last_handshake_at(&self, now: Instant) -> Option<Duration> {
        if self.sessions[self.current].is_some() {
            let session_established_at = self.timers[TimeSessionEstablished];

            Some(now.duration_since(session_established_at))
        } else {
            None
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}
