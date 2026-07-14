//! A deterministic test harness that drives two [`Tunn`] instances against
//! each other over an in-memory network with a virtual clock.
//!
//! Time only moves when a test says so ([`Sim::advance`]), packets only flow
//! when routed ([`Sim::route`]) or hand-delivered ([`Sim::deliver`]), and all
//! routed traffic is recorded in [`Sim::log`] so tests can assert *what* was
//! sent *when*.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Index, Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

// Protocol constants from the WireGuard whitepaper (§6.1, table on p. 14).
// They are deliberately redefined here instead of imported: the tests assert
// that the implementation conforms to the paper, not to itself.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
/// Handshake initiations are delayed by a random jitter of up to 333ms (§6.1).
pub const MAX_JITTER: Duration = Duration::from_millis(333);

/// boringtun stops *initiating* on a session `KEEPALIVE_TIMEOUT` before
/// `REJECT_AFTER_TIME`, so that packets sent just before the deadline can
/// still be decrypted by the peer (implementation-specific safety margin).
pub const SHOULD_NOT_USE_AFTER_TIME: Duration = Duration::from_secs(180 - 10);

/// A data message carries 16 bytes of header plus a 16-byte AEAD tag (§5.4.6).
pub const DATA_OVERHEAD: usize = 32;
/// A keepalive is a data message with an empty payload (§6.1).
pub const KEEPALIVE_SIZE: usize = DATA_OVERHEAD;
pub const HANDSHAKE_INIT_SIZE: usize = 148;
pub const HANDSHAKE_RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;

/// boringtun's anti-replay window: 128 words of 64 bits each
/// (implementation-specific; the paper's reference window is 2000 packets).
pub const REPLAY_WINDOW: u64 = 8192;

/// Granularity at which [`Sim::advance`] polls `update_timers_at`.
pub const TICK: Duration = Duration::from_millis(100);

const BUF: usize = 4096;

pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Peer {
    A,
    B,
}

impl Peer {
    pub fn other(self) -> Peer {
        match self {
            Peer::A => Peer::B,
            Peer::B => Peer::A,
        }
    }
}

/// What a datagram on the simulated wire is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Init,
    Response,
    CookieReply,
    Data,
    Keepalive,
}

pub fn classify(datagram: &[u8]) -> Kind {
    match Tunn::parse_incoming_packet(datagram).expect("only valid packets should be routed") {
        Packet::HandshakeInit(_) => Kind::Init,
        Packet::HandshakeResponse(_) => Kind::Response,
        Packet::PacketCookieReply(_) => Kind::CookieReply,
        Packet::PacketData(_) if datagram.len() == KEEPALIVE_SIZE => Kind::Keepalive,
        Packet::PacketData(_) => Kind::Data,
    }
}

/// The receiver index of a data message, identifying the session it uses.
pub fn receiver_index(datagram: &[u8]) -> u32 {
    match Tunn::parse_incoming_packet(datagram).unwrap() {
        Packet::PacketData(p) => p.receiver_idx,
        other => panic!("not a data packet: {other:?}"),
    }
}

/// A datagram observed on the simulated wire.
#[derive(Debug)]
pub struct Event {
    /// Time since the start of the simulation.
    pub at: Duration,
    pub from: Peer,
    pub kind: Kind,
}

/// The result of feeding a single datagram into one peer.
#[derive(Debug)]
pub enum Out {
    /// A decrypted IP packet destined for the tunnel interface.
    Ip(Vec<u8>),
    /// A datagram to be sent back over the network.
    Net(Vec<u8>),
    Err(WireGuardError),
}

pub trait Outcome {
    fn expect_one_ip(self) -> Vec<u8>;
    fn expect_one_net(self) -> Vec<u8>;
    fn expect_err(self) -> WireGuardError;
    fn expect_consumed(self);
}

impl Outcome for Vec<Out> {
    #[track_caller]
    fn expect_one_ip(self) -> Vec<u8> {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Ip(p)]) => p,
            other => panic!("expected a single IP packet, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_one_net(self) -> Vec<u8> {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Net(p)]) => p,
            other => panic!("expected a single network packet, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_err(self) -> WireGuardError {
        match <[Out; 1]>::try_from(self) {
            Ok([Out::Err(e)]) => e,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[track_caller]
    fn expect_consumed(self) {
        assert!(
            self.is_empty(),
            "expected the packet to be consumed silently, got {self:?}"
        );
    }
}

struct Node {
    tunn: Tunn,
    addr: IpAddr,
    inbox: Vec<Vec<u8>>,
    errors: Vec<WireGuardError>,
    drop_outgoing: bool,
}

pub struct Builder {
    psk_a: Option<[u8; 32]>,
    psk_b: Option<[u8; 32]>,
    persistent_keepalive_b: Option<u16>,
    seed_a: u64,
    seed_b: u64,
    responder_under_load: bool,
    responder_expects_different_key: bool,
}

impl Builder {
    pub fn psk_a(mut self, psk: [u8; 32]) -> Self {
        self.psk_a = Some(psk);
        self
    }

    pub fn psk_b(mut self, psk: [u8; 32]) -> Self {
        self.psk_b = Some(psk);
        self
    }

    pub fn persistent_keepalive_b(mut self, interval_secs: u16) -> Self {
        self.persistent_keepalive_b = Some(interval_secs);
        self
    }

    pub fn seeds(mut self, seed_a: u64, seed_b: u64) -> Self {
        self.seed_a = seed_a;
        self.seed_b = seed_b;
        self
    }

    /// Give the responder a rate limiter that considers it permanently under
    /// load, forcing the cookie mechanism (§5.3) on every handshake.
    pub fn responder_under_load(mut self) -> Self {
        self.responder_under_load = true;
        self
    }

    /// Configure the responder to expect a different static public key than
    /// the initiator's.
    pub fn responder_expects_different_key(mut self) -> Self {
        self.responder_expects_different_key = true;
        self
    }

    pub fn build(self) -> Sim {
        let start = Instant::now();
        let unix = Duration::from_secs(1_700_000_000);

        let secret_a = StaticSecret::random();
        let public_a = PublicKey::from(&secret_a);
        let secret_b = StaticSecret::random();
        let public_b = PublicKey::from(&secret_b);

        let a = Tunn::new_at(
            secret_a,
            public_b,
            self.psk_a.map(StaticSecret::from),
            None,
            Index::new_local(1),
            None,
            self.seed_a,
            start,
            start,
            unix,
        );

        let expected_by_b = if self.responder_expects_different_key {
            PublicKey::from(&StaticSecret::random())
        } else {
            public_a
        };
        let rate_limiter = self
            .responder_under_load
            .then(|| Arc::new(RateLimiter::new_at(&public_b, 0, start)));
        let b = Tunn::new_at(
            secret_b,
            expected_by_b,
            self.psk_b.map(StaticSecret::from),
            self.persistent_keepalive_b,
            Index::new_local(2),
            rate_limiter,
            self.seed_b,
            start,
            start,
            unix,
        );

        Sim {
            start,
            now: start,
            nodes: [
                Node {
                    tunn: a,
                    addr: "10.0.0.1".parse().unwrap(),
                    inbox: Vec::new(),
                    errors: Vec::new(),
                    drop_outgoing: false,
                },
                Node {
                    tunn: b,
                    addr: "10.0.0.2".parse().unwrap(),
                    inbox: Vec::new(),
                    errors: Vec::new(),
                    drop_outgoing: false,
                },
            ],
            log: Vec::new(),
        }
    }
}

/// Two [`Tunn`] instances (`A`, the conventional initiator, and `B`, the
/// responder) connected by a simulated network.
pub struct Sim {
    start: Instant,
    pub now: Instant,
    nodes: [Node; 2],
    pub log: Vec<Event>,
}

impl Sim {
    pub fn builder() -> Builder {
        Builder {
            psk_a: None,
            psk_b: None,
            persistent_keepalive_b: None,
            seed_a: 1,
            seed_b: 2,
            responder_under_load: false,
            responder_expects_different_key: false,
        }
    }

    /// A fresh pair without an established session.
    pub fn new() -> Sim {
        Sim::builder().build()
    }

    /// A pair with a completed handshake and an empty packet log.
    pub fn connected() -> Sim {
        let mut sim = Sim::new();
        sim.establish();
        sim.clear_log();
        sim
    }

    fn node(&self, peer: Peer) -> &Node {
        &self.nodes[peer as usize]
    }

    fn node_mut(&mut self, peer: Peer) -> &mut Node {
        &mut self.nodes[peer as usize]
    }

    pub fn tunn(&self, peer: Peer) -> &Tunn {
        &self.node(peer).tunn
    }

    pub fn tunn_mut(&mut self, peer: Peer) -> &mut Tunn {
        &mut self.node_mut(peer).tunn
    }

    pub fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Whether `peer` currently has a usable session.
    pub fn is_established(&self, peer: Peer) -> bool {
        self.tunn(peer)
            .time_since_last_handshake_at(self.now)
            .is_some()
    }

    pub fn errors(&self, peer: Peer) -> &[WireGuardError] {
        &self.node(peer).errors
    }

    pub fn take_inbox(&mut self, peer: Peer) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.node_mut(peer).inbox)
    }

    // --- Network fault injection ---

    /// Drop all packets in both directions from now on.
    pub fn cut_link(&mut self) {
        self.nodes[0].drop_outgoing = true;
        self.nodes[1].drop_outgoing = true;
    }

    pub fn heal_link(&mut self) {
        self.nodes[0].drop_outgoing = false;
        self.nodes[1].drop_outgoing = false;
    }

    // --- Driving the tunnels ---

    /// Advance the virtual clock, polling `update_timers_at` on both peers
    /// every [`TICK`] and routing whatever they emit.
    pub fn advance(&mut self, duration: Duration) {
        let end = self.now + duration;
        while self.now < end {
            self.now = std::cmp::min(self.now + TICK, end);
            self.poll(Peer::A);
            self.poll(Peer::B);
        }
    }

    fn poll(&mut self, peer: Peer) {
        let now = self.now;
        let mut buf = vec![0u8; BUF];
        let outgoing = match self.node_mut(peer).tunn.update_timers_at(&mut buf, now) {
            TunnResult::Done => None,
            TunnResult::Err(e) => {
                self.node_mut(peer).errors.push(e);
                None
            }
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            other => panic!("unexpected result from update_timers_at: {other:?}"),
        };

        if let Some(datagram) = outgoing {
            self.route(peer, datagram);
        }
    }

    /// Put a datagram on the wire and let the peers exchange packets until the
    /// network is quiet. Every datagram is logged, dropped datagrams included.
    pub fn route(&mut self, from: Peer, datagram: Vec<u8>) {
        let mut in_flight = VecDeque::from([(from, datagram)]);
        let mut hops = 0;

        while let Some((from, datagram)) = in_flight.pop_front() {
            hops += 1;
            assert!(
                hops < 64,
                "too many packets in flight; is the tunnel looping?"
            );

            self.log.push(Event {
                at: self.elapsed(),
                from,
                kind: classify(&datagram),
            });

            if self.node(from).drop_outgoing {
                continue;
            }

            let to = from.other();
            for out in self.deliver(to, &datagram) {
                match out {
                    Out::Net(reply) => in_flight.push_back((to, reply)),
                    Out::Ip(packet) => self.node_mut(to).inbox.push(packet),
                    Out::Err(e) => self.node_mut(to).errors.push(e),
                }
            }
        }
    }

    /// Feed a single datagram into `to`, bypassing the network (and thus the
    /// log and any link faults). Replies are returned, not routed.
    pub fn deliver(&mut self, to: Peer, datagram: &[u8]) -> Vec<Out> {
        let src = Some(self.node(to.other()).addr);
        self.deliver_from(to, datagram, src)
    }

    /// Like [`Sim::deliver`] but without a source address, as if the transport
    /// could not provide one.
    pub fn deliver_anonymous(&mut self, to: Peer, datagram: &[u8]) -> Vec<Out> {
        self.deliver_from(to, datagram, None)
    }

    fn deliver_from(&mut self, to: Peer, datagram: &[u8], src: Option<IpAddr>) -> Vec<Out> {
        let now = self.now;
        let node = self.node_mut(to);
        let mut outs = Vec::new();

        let mut buf = vec![0u8; BUF];
        match node.tunn.decapsulate_at(src, datagram, &mut buf, now) {
            TunnResult::Done => {}
            TunnResult::Err(e) => outs.push(Out::Err(e)),
            TunnResult::WriteToTunnelV4(packet, _) => outs.push(Out::Ip(packet.to_vec())),
            TunnResult::WriteToTunnelV6(packet, _) => outs.push(Out::Ip(packet.to_vec())),
            TunnResult::WriteToNetwork(packet) => {
                outs.push(Out::Net(packet.to_vec()));

                // Per the `decapsulate_at` contract, keep calling with an
                // empty datagram to flush packets queued while no session
                // existed. The queue only exists with the `packet-queue`
                // feature.
                #[cfg(feature = "packet-queue")]
                loop {
                    let mut buf = vec![0u8; BUF];
                    match node.tunn.decapsulate_at(None, &[], &mut buf, now) {
                        TunnResult::Done => break,
                        TunnResult::WriteToNetwork(packet) => outs.push(Out::Net(packet.to_vec())),
                        other => panic!("unexpected result while flushing queue: {other:?}"),
                    }
                }
            }
        }

        outs
    }

    // --- Handshakes ---

    /// Create (but do not deliver) a handshake initiation from `peer`.
    #[track_caller]
    pub fn initiate_handshake(&mut self, peer: Peer) -> Vec<u8> {
        self.handshake_initiation(peer, false)
            .expect("a handshake initiation to be emitted")
    }

    /// Like [`Sim::initiate_handshake`], but also when one is already in flight.
    #[track_caller]
    pub fn force_handshake_initiation(&mut self, peer: Peer) -> Vec<u8> {
        self.handshake_initiation(peer, true)
            .expect("a handshake initiation to be emitted")
    }

    fn handshake_initiation(&mut self, peer: Peer, force: bool) -> Option<Vec<u8>> {
        let now = self.now;
        let mut buf = vec![0u8; BUF];
        match self
            .node_mut(peer)
            .tunn
            .format_handshake_initiation_at(&mut buf, force, now)
        {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            TunnResult::Done => None,
            other => panic!("unexpected result from format_handshake_initiation_at: {other:?}"),
        }
    }

    /// Complete a full handshake initiated by `A`.
    #[track_caller]
    pub fn establish(&mut self) {
        let init = self.initiate_handshake(Peer::A);
        self.route(Peer::A, init);

        assert!(
            self.is_established(Peer::A),
            "initiator has no session after handshake"
        );
        assert!(
            self.is_established(Peer::B),
            "responder has no session after handshake"
        );
    }

    // --- Data transfer ---

    /// Encrypt an IP packet on the current session, panicking if there is none.
    #[track_caller]
    pub fn encapsulate(&mut self, from: Peer, ip_packet: &[u8]) -> Vec<u8> {
        self.try_encapsulate(from, ip_packet)
            .expect("an active session")
    }

    pub fn try_encapsulate(
        &mut self,
        from: Peer,
        ip_packet: &[u8],
    ) -> Result<Vec<u8>, WireGuardError> {
        let now = self.now;
        let mut buf = vec![0u8; BUF];
        let len = self
            .node_mut(from)
            .tunn
            .encapsulate_data_at(ip_packet, &mut buf, now)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Encrypt an IP packet if a session exists; otherwise queue it internally
    /// and return the handshake initiation that takes its place on the wire.
    #[cfg(feature = "packet-queue")]
    pub fn encapsulate_or_queue(&mut self, from: Peer, ip_packet: &[u8]) -> Option<Vec<u8>> {
        let now = self.now;
        let mut buf = vec![0u8; BUF];
        match self
            .node_mut(from)
            .tunn
            .encapsulate_at(ip_packet, &mut buf, now)
        {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            TunnResult::Done => None,
            other => panic!("unexpected result from encapsulate_at: {other:?}"),
        }
    }

    /// Encrypt an IP packet and route it through the network.
    pub fn send_ip(&mut self, from: Peer, ip_packet: &[u8]) {
        let datagram = self.encapsulate(from, ip_packet);
        self.route(from, datagram);
    }

    /// Send one IP packet in each direction and assert that both arrive.
    #[track_caller]
    pub fn assert_connectivity(&mut self) {
        for from in [Peer::A, Peer::B] {
            let ip_packet = ipv4_packet(format!("ping from {from:?}").as_bytes());
            self.send_ip(from, &ip_packet);

            let received = self
                .node_mut(from.other())
                .inbox
                .pop()
                .unwrap_or_else(|| panic!("{:?} did not receive the packet", from.other()));
            assert_eq!(received, ip_packet);
        }
    }

    // --- Log queries ---

    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Times (since simulation start) at which `from` sent packets of `kind`.
    pub fn sent_at(&self, from: Peer, kind: Kind) -> Vec<Duration> {
        self.log
            .iter()
            .filter(|e| e.from == from && e.kind == kind)
            .map(|e| e.at)
            .collect()
    }

    pub fn count(&self, from: Peer, kind: Kind) -> usize {
        self.sent_at(from, kind).len()
    }
}

// --- Assertion helpers ---

/// Assert that a (possibly jittered) timer event fired at `expected`:
/// no earlier, and no later than jitter plus polling granularity allow.
#[track_caller]
pub fn assert_fires_at(actual: Duration, expected: Duration) {
    let latest = expected + MAX_JITTER + 2 * TICK;
    assert!(
        (expected..=latest).contains(&actual),
        "event fired at {actual:?}, expected between {expected:?} and {latest:?}"
    );
}

/// Assert that an unjittered timer event fired at `expected`, give or take
/// polling granularity.
#[track_caller]
pub fn assert_close(actual: Duration, expected: Duration) {
    assert!(
        actual.abs_diff(expected) <= 2 * TICK,
        "event fired at {actual:?}, expected {expected:?} (±{:?})",
        2 * TICK
    );
}

// --- Test IP packets ---

pub fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
    let builder =
        etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64).udp(1111, 2222);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

pub fn ipv6_packet(payload: &[u8]) -> Vec<u8> {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let builder = etherparse::PacketBuilder::ipv6(src, dst, 64).udp(1111, 2222);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}
