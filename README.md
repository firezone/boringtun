# BoringTun

This is a fork of [BoringTun](https://github.com/cloudflare/boringtun), heavily modified for [Firezone](https://github.com/firezone/firezone).
It has no API compatibility with upstream: anything Firezone does not use has been removed.
The last commit that is still API-compatible with upstream is [`0702986`](https://github.com/firezone/boringtun/tree/0702986446add9a79efdb4934042a2043ba1e3de).

Compared to upstream, this fork:

- is sans-IO: every time-dependent function takes the current `Instant` and randomness comes from a caller-provided seed, so `Tunn` never reads the clock and behaves deterministically.
- reports the exact instant it next needs to be polled via `Tunn::next_timer_update`, so callers can sleep until then instead of ticking `update_timers` every second.
- encrypts data in place with `Tunn::encapsulate_data_at`, which has no side effects without a session: there is no internal packet queue and the caller decides when to handshake.
- fixes many bugs in the timer and handshake state machine, such as duplicate or spurious handshake initiations, responders initiating rekeys, sending on sessions about to expire and deadlines that never fire.
- returns errors instead of panicking when a destination buffer is too small.
- holds the preshared key in a zeroizing `StaticSecret` and tolerates up to 8192 reordered packets, in line with the Linux kernel implementation.
- makes `REKEY_ATTEMPT_TIME`, `KEEPALIVE_TIMEOUT` and `REKEY_TIMEOUT` configurable.

## License

The project is licensed under the [3-Clause BSD License](LICENSE.md).

<sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTun is not sponsored or endorsed by Jason A. Donenfeld.</sub>
