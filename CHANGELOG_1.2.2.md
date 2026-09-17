# SplitWire 1.2.2

This release consolidates the dataplane/UI fixes developed after 1.2.1. The source tree is unit/race/vet tested, Windows-amd64 cross-vetted/cross-built, and checked against an independent Python WireGuard responder. Live WinDivert validation still has to be performed on a Windows machine because the build environment cannot load the driver or reproduce the user's corporate-VPN/Discord/ChatGPT/YouTube setup.

## Process attribution and sticky routing

- WinDivert SOCKET-layer attribution is used before FLOW/IP Helper fallback, so bind/connect ownership is available earlier than the first packet whenever Windows exposes it.
- Wildcard SOCKET_BIND addresses (`0.0.0.0`/`::`) are normalized and participate in lookup correctly.
- SOCKET ownership is keyed by WinDivert `EndpointId`; a late close from an old socket cannot delete ownership of a newly reused local port.
- FLOW owns exact 5-tuples; SOCKET owns live local endpoints; IP Helper snapshots are fallback state only. Periodic IP Helper refresh atomically replaces the fallback snapshot instead of accumulating stale PID/port entries. The three lifetime sources no longer create conflicting durable entries.
- Per-flow route decisions are sticky. A flow cannot switch DIRECT <-> WireGuard midway through a connection.
- Selected TCP flows that existed before SplitWire starts are reset once, forcing the application to create a fresh connection on the selected route.
- UDP local-endpoint ownership survives deletion of one implicit remote FLOW and is removed by the real SOCKET_CLOSE.

## MTU, LSO and IP fragmentation

- Oversized Windows TCP LSO packets are software-segmented to the configured inner MTU before WireGuard encryption.
- TCP MSS is clamped on outbound SYN and inbound SYN/SYN-ACK.
- The WireGuard client rejects an inner packet larger than the configured MTU instead of silently emitting an oversized encrypted datagram.
- IPv4 fragments, including the first `offset=0, MF=1` fragment, are classified as fragments rather than normal TCP/UDP packets.
- The WinDivert network filter explicitly captures `fragment`, so non-initial fragments cannot bypass policy simply because they have no transport header.
- IPv4 and ordinary IPv6 Fragment-header traffic is reassembled before process/policy/NAT decisions. DIRECT traffic is re-fragmented before reinjection when required.
- Oversized UDP is checksummed as a complete NATed datagram and then IP-fragmented; it is never byte-sliced like TCP.
- Malformed/unsupported fragments fail closed and are counted. Incomplete reassembly TTL expiry is visible as `fragTimeouts`, increments drop/error diagnostics, and produces a log record.

## Queueing and WireGuard receive path

- Latency-sensitive UDP uses an urgent queue, but priority is bounded (8 urgent packets then a ready bulk packet) so continuous voice traffic cannot starve bulk TCP forever.
- WinDivert queue limits and WireGuard UDP socket buffers are increased.
- Queue high-water and maximum queue delay are measured.
- WireGuard RX no longer stops reading the UDP socket while waiting for a full plaintext channel. The plaintext queue is non-blocking and exposes an explicit `plainDrop` counter.
- WireGuard RX diagnostics cover raw receive, wrong endpoint, short/unknown packets, missing sessions, authentication failure, replay drops, invalid inner packets, plaintext queue high-water/drop and transport receive.
- AEAD authentication is completed before replay-window mutation.
- Reverse-NAT misses and injection/write failures have explicit counters/logging instead of silent `continue` paths.

## DNS, proxy and default rules

- Literal `DNS = ...` addresses in the WireGuard `[Interface]` section are parsed and used by SplitWire's own tunneled hostname resolver. Global Windows DNS is not modified.
- Proxy dials respect the address family available in the WireGuard interface configuration.
- PAC-selected hosts no longer have a `PROXY ...; DIRECT` escape path.
- Proxy stream copy failures are logged with direction and transferred-byte count.
- The default messenger group includes `Discord.exe`, `DiscordSystemHelper.exe` and `Telegram.exe`.
- The default config adds a full-app `ChatGPT.exe` group and keeps browser ChatGPT/OpenAI matching in the AI group.
- ChatGPT/OpenAI and YouTube hostname sets are expanded for current auth/upload/challenge/API/static dependencies.

## GUI logging

- One `log.Logger` writes through `loghub.Hub` to both the physical `splitwire.log` file and a bounded in-memory UI sink.
- The file is read only once at startup to seed visible history; there is no periodic file polling.
- New log text is delivered as an in-memory delta. `PostMessage` is only a coalesced wake-up for the GUI thread, never the transport for log bytes.
- If the GUI falls too far behind for a safe delta, the sink requests a bounded full resync instead of silently truncating/duplicating text.

## Validation

Release builds use `-buildvcs=false -trimpath` so rebuilding from the packaged source tree does not depend on local Git metadata. See `TEST_RESULTS.txt` for the exact commands, binary identification and SHA-256 of the packaged executable.
