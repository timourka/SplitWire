# SplitWire 1.2.1

Stability release focused on real-time UDP and hostname discovery.

## Fixed

- Periodic WireGuard rekey no longer blocks the packet send path. The current session remains usable while the replacement handshake runs in the background.
- A failed background rekey keeps the current still-valid session instead of immediately stopping traffic.
- Removed blind resets of already-established TLS connections whose hostname is unknown. Only an actually matched SNI flow may be reconnected through WireGuard.
- Aggressive QUIC suppression is disabled during normal PAC mode and is enabled only when PAC setup fails.
- Hostname discovery accounting is limited to relevant TCP/UDP port 443 traffic instead of counting almost every packet when a global `Apps = *` domain group exists.
- Periodic key rotation is logged explicitly as `rekey (non-blocking)` so it is not confused with a tunnel failure.

## Why

The previous implementation refreshed the WireGuard key synchronously from `SendPacket` at about 110 seconds. Even a successful handshake could pause queued real-time UDP for the handshake RTT. In parallel, the TLS fallback could reset unrelated established browser HTTPS flows just to rediscover their SNI. Both behaviors were unnecessary in normal PAC mode and could create visible instability.
