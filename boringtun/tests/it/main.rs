//! Behavioural integration tests for boringtun's sans-IO WireGuard
//! implementation ([`boringtun::noise::Tunn`]).
//!
//! All tests drive two `Tunn` instances against each other through the public
//! API only, on a virtual clock (see [`harness`]). They are grounded in the
//! WireGuard whitepaper (<https://www.wireguard.com/papers/wireguard.pdf>):
//!
//! - §5.3: cookies and DoS mitigation (`cookies`)
//! - §5.4: protocol messages (`handshake`, `data`)
//! - §5.4.6, §6.4: nonce-based replay protection (`replay`)
//! - §6.1-§6.5: timers, keepalives and passive stealth (`timers`)
//!
//! Behaviour specific to the sans-IO design - explicit time injection,
//! `next_timer_update`, jittered handshake scheduling and the internal packet
//! queue - is covered in `sans_io`.

mod cookies;
mod data;
mod handshake;
mod harness;
mod replay;
mod sans_io;
mod timers;
