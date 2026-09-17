# SplitWire 1.2.2-dnsfix1

- Fixed tunneled DNS timeouts in the hostname proxy: the route-registration wrapper now preserves `net.PacketConn` for UDP sockets. Go `net.Resolver` relies on that interface to choose DNS datagram framing; hiding it caused TCP length-prefixed DNS messages to be sent inside UDP datagrams.
- If the configured WireGuard DNS resolver is genuinely unreachable, hostname resolution now falls back to the Windows/system resolver while the actual upstream ChatGPT/YouTube connection remains routed through WireGuard.
- Diagnostics now include `otherIn`, counting decrypted non-TCP/UDP inner packets that cannot participate in reverse NAT.
- UI version string changed to `1.2.2-dnsfix1`.
