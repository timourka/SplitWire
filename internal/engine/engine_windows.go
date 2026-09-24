//go:build windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"splitwire/internal/browserdisc"
	"splitwire/internal/config"
	"splitwire/internal/domain"
	"splitwire/internal/flow"
	"splitwire/internal/nat"
	"splitwire/internal/packet"
	"splitwire/internal/policy"
	"splitwire/internal/reassembly"
	"splitwire/internal/windivert"
	"splitwire/internal/wireguard"
)

type Logf func(string, ...any)

type Status struct {
	Captured, Tunneled, Bypassed, Dropped, WGTxBytes, WGRxBytes                                                                       uint64
	DomainIPs                                                                                                                         int
	LastHandshake                                                                                                                     time.Time
	ProcessResolved, ProcessMissed, DiscoveryPackets, DomainMatches, SNILearned, QUICSuppressed, Reconnects, ProxyTunnel, ProxyDirect uint64
	WGWriteOK, WGWriteErrors, ReverseNATMiss, InboundInjected, InboundErrors, InboundOther                                            uint64
	OversizeSegmented, OversizeDropped, SendQueueHigh, SendQueueDelayMaxMS                                                            uint64
	StickyUnknownDirect, PreexistingTCPReset                                                                                          uint64
	WGRawRX, WGNoSession, WGAuthFail, WGReplayDrop, WGInvalidInner, WGPlainQHigh, WGPlainDrop                                         uint64
	FragReassembled, FragRefragmented, FragErrors, FragTimeouts                                                                       uint64
}

type Runner struct {
	cfg                                                                                               *config.Config
	ifaceIndex                                                                                        uint32
	ifaceName                                                                                         string
	logf                                                                                              Logf
	flows                                                                                             *flow.Index
	domains                                                                                           *domain.Tracker
	discovery                                                                                         *browserdisc.Discovery
	policy                                                                                            *policy.Engine
	proxyRoutes                                                                                       *proxyRouteTable
	routes                                                                                            *flowRouteTable
	nat                                                                                               *nat.Mapper
	out4, in4                                                                                         *reassembly.IPv4
	out6, in6                                                                                         *reassembly.IPv6
	wg                                                                                                *wireguard.Client
	netHandle, flowHandle, dnsHandle, socketHandle                                                    *windivert.Handle
	dnsResolver                                                                                       *net.Resolver
	cancel                                                                                            context.CancelFunc
	wgDone                                                                                            sync.WaitGroup
	closeOnce                                                                                         sync.Once
	captured, tunneled, bypassed, dropped                                                             atomic.Uint64
	procResolved, procMissed, discoveryPackets, domainMatches, sniLearned, quicSuppressed, reconnects atomic.Uint64
	proxyTunnel, proxyDirect                                                                          atomic.Uint64
	wgWriteOK, wgWriteErrors, reverseNATMiss, inboundInjected, inboundErrors, inboundOther            atomic.Uint64
	oversizeSegmented, oversizeDropped, sendQueueHigh, sendQueueDelayMaxMS                            atomic.Uint64
	stickyUnknownDirect, preexistingTCPReset                                                          atomic.Uint64
	fragReassembled, fragRefragmented, fragErrors, fragTimeouts                                       atomic.Uint64
	aggressiveDiscovery                                                                               atomic.Bool
}

type Params struct {
	Config            *config.Config
	InterfaceIndex    uint32
	InterfaceName     string
	InternalProcesses []string
	Logf              Logf
}
type queuedPacket struct {
	raw    []byte
	queued time.Time
}

func Start(parent context.Context, p Params) (*Runner, error) {
	if p.Config == nil {
		return nil, fmt.Errorf("nil config")
	}
	priv, err := config.DecodeKey(p.Config.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := config.DecodeKey(p.Config.Peer.PublicKey)
	if err != nil {
		return nil, err
	}
	var psk [32]byte
	if p.Config.Peer.PresharedKey != "" {
		psk, err = config.DecodeKey(p.Config.Peer.PresharedKey)
		if err != nil {
			return nil, err
		}
	}
	wg, err := wireguard.New(wireguard.Params{PrivateKey: priv, PeerPublicKey: pub, PresharedKey: psk, Endpoint: p.Config.Peer.Endpoint, InterfaceIndex: p.InterfaceIndex, MTU: p.Config.MTU, Keepalive: p.Config.Peer.PersistentKeepalive, Logf: p.Logf})
	if err != nil {
		return nil, fmt.Errorf("WireGuard: %w", err)
	}
	cleanupWG := true
	defer func() {
		if cleanupWG {
			_ = wg.Close()
		}
	}()
	// Explicitly include fragment packets. A non-initial fragment has no TCP/UDP
	// header, so a transport-only filter would otherwise let pieces of the same
	// datagram escape classification by different routes.
	outer0, outer1 := wg.LocalPorts()
	filter := fmt.Sprintf("outbound and !loopback and !impostor and ((tcp or (udp and udp.SrcPort != %d and udp.SrcPort != %d)) or fragment)", outer0, outer1)
	nh, err := windivert.OpenNetwork(filter, 0, 0)
	if err != nil {
		return nil, err
	}
	cleanupN := true
	defer func() {
		if cleanupN {
			_ = nh.Close()
		}
	}()
	if err := nh.TuneQueue(); err != nil && p.Logf != nil {
		p.Logf("WinDivert queue tuning unavailable: %v", err)
	}
	fh, err := windivert.OpenFlow("true", 100)
	if err != nil {
		return nil, err
	}
	cleanupF := true
	defer func() {
		if cleanupF {
			_ = fh.Close()
		}
	}()
	dh, err := windivert.OpenNetwork("inbound and udp and udp.SrcPort == 53", -100, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		return nil, err
	}
	cleanupD := true
	defer func() {
		if cleanupD {
			_ = dh.Close()
		}
	}()
	sh, shErr := windivert.OpenSocket("true", 110)
	if shErr != nil && p.Logf != nil {
		p.Logf("WinDivert SOCKET ownership unavailable, using FLOW/IP Helper fallback: %v", shErr)
	}
	cleanupS := sh != nil
	defer func() {
		if cleanupS {
			_ = sh.Close()
		}
	}()

	tr := domain.New(p.Config.Groups)
	v4, _ := p.Config.TunnelIPv4()
	v6, _ := p.Config.TunnelIPv6()
	ctx, cancel := context.WithCancel(parent)
	r := &Runner{cfg: p.Config, ifaceIndex: p.InterfaceIndex, ifaceName: p.InterfaceName, logf: p.Logf, flows: flow.New(), domains: tr, discovery: browserdisc.New(), proxyRoutes: newProxyRouteTable(), routes: newFlowRouteTable(), nat: nat.New(v4, v6), out4: reassembly.NewIPv4(), in4: reassembly.NewIPv4(), out6: reassembly.NewIPv6(), in6: reassembly.NewIPv6(), wg: wg, netHandle: nh, flowHandle: fh, dnsHandle: dh, socketHandle: sh, cancel: cancel}
	r.policy = policy.NewWithInternal(p.Config, tr, p.InternalProcesses)
	r.dnsResolver = newTunnelDNSResolver(p.Config.DNSServers, r.proxyRoutes)
	if len(p.Config.DNSServers) > 0 {
		r.log("WireGuard DNS for tunneled hostname resolution: %v (registered UDP/TCP sockets; system DNS fallback enabled)", p.Config.DNSServers)
	}

	if tcpN, udpN, snapErr := r.flows.SnapshotExisting(windivert.ProcessInfo); snapErr != nil {
		r.log("initial socket ownership snapshot partially failed: %v", snapErr)
	} else {
		r.log("imported existing socket ownership: TCP=%d UDP=%d", tcpN, udpN)
	}

	urgentQ := make(chan queuedPacket, 4096)
	bulkQ := make(chan queuedPacket, 8192)
	// Capture must be alive before bootstrap uses the tunnel-aware DNS resolver.
	r.goRun(func() { r.flowLoop(ctx) })
	if sh != nil {
		r.goRun(func() { r.socketLoop(ctx) })
	}
	r.goRun(func() { r.dnsLoop(ctx) })
	r.goRun(func() { r.wgReceiveLoop(ctx) })
	r.goRun(func() { r.sendLoop(ctx, urgentQ, bulkQ) })
	r.goRun(func() { r.captureLoop(ctx, urgentQ, bulkQ) })
	r.goRun(func() { r.bootstrapLoop(ctx) })
	r.goRun(func() { r.maintenanceLoop(ctx) })
	r.goRun(func() { r.diagnosticLoop(ctx) })
	r.goRun(func() { r.socketSnapshotLoop(ctx) })
	cleanupWG = false
	cleanupN = false
	cleanupF = false
	cleanupD = false
	cleanupS = false
	r.log("started on physical interface %s (%d), outer UDP active=%d standby=%d", p.InterfaceName, p.InterfaceIndex, wg.LocalPort(), wg.StandbyPort())
	return r, nil
}
func (r *Runner) goRun(fn func()) { r.wgDone.Add(1); go func() { defer r.wgDone.Done(); fn() }() }
func (r *Runner) log(f string, a ...any) {
	if r.logf != nil {
		r.logf(f, a...)
	}
}
func (r *Runner) Close() {
	r.closeOnce.Do(func() {
		r.cancel()
		_ = r.netHandle.Close()
		_ = r.flowHandle.Close()
		_ = r.dnsHandle.Close()
		if r.socketHandle != nil {
			_ = r.socketHandle.Close()
		}
		r.wgDone.Wait()
		_ = r.wg.Close()
		r.log("stopped")
	})
}
func (r *Runner) Interface() string { return fmt.Sprintf("%s (%d)", r.ifaceName, r.ifaceIndex) }
func (r *Runner) SetAggressiveDiscovery(v bool) {
	r.aggressiveDiscovery.Store(v)
	r.log("aggressive hostname discovery: %v", v)
}
func (r *Runner) Status() Status {
	tx, rx := r.wg.Stats()
	wd := r.wg.Diagnostics()
	return Status{Captured: r.captured.Load(), Tunneled: r.tunneled.Load(), Bypassed: r.bypassed.Load(), Dropped: r.dropped.Load(), WGTxBytes: tx, WGRxBytes: rx, DomainIPs: r.domains.Count(), LastHandshake: r.wg.LastHandshake(), ProcessResolved: r.procResolved.Load(), ProcessMissed: r.procMissed.Load(), DiscoveryPackets: r.discoveryPackets.Load(), DomainMatches: r.domainMatches.Load(), SNILearned: r.sniLearned.Load(), QUICSuppressed: r.quicSuppressed.Load(), Reconnects: r.reconnects.Load(), ProxyTunnel: r.proxyTunnel.Load(), ProxyDirect: r.proxyDirect.Load(), WGWriteOK: r.wgWriteOK.Load(), WGWriteErrors: r.wgWriteErrors.Load(), ReverseNATMiss: r.reverseNATMiss.Load(), InboundInjected: r.inboundInjected.Load(), InboundErrors: r.inboundErrors.Load(), InboundOther: r.inboundOther.Load(), OversizeSegmented: r.oversizeSegmented.Load(), OversizeDropped: r.oversizeDropped.Load(), SendQueueHigh: r.sendQueueHigh.Load(), SendQueueDelayMaxMS: r.sendQueueDelayMaxMS.Load(), StickyUnknownDirect: r.stickyUnknownDirect.Load(), PreexistingTCPReset: r.preexistingTCPReset.Load(), WGRawRX: wd.RawRX, WGNoSession: wd.NoSession, WGAuthFail: wd.AuthFail, WGReplayDrop: wd.ReplayDrop, WGInvalidInner: wd.InvalidInner, WGPlainQHigh: wd.PlainQHigh, WGPlainDrop: wd.PlainDrop, FragReassembled: r.fragReassembled.Load(), FragRefragmented: r.fragRefragmented.Load(), FragErrors: r.fragErrors.Load(), FragTimeouts: r.fragTimeouts.Load()}
}
func updateMax(a *atomic.Uint64, v uint64) {
	for {
		old := a.Load()
		if v <= old || a.CompareAndSwap(old, v) {
			return
		}
	}
}

func (r *Runner) noteFragmentTimeouts(n uint64) {
	if n == 0 {
		return
	}
	r.fragTimeouts.Add(n)
	r.fragErrors.Add(n)
	r.dropped.Add(n)
	r.log("fragment reassembly timeout: %d incomplete datagram(s)", n)
}

func (r *Runner) takeFragmentTimeouts(v4 *reassembly.IPv4, v6 *reassembly.IPv6) {
	r.noteFragmentTimeouts(v4.TakeExpired() + v6.TakeExpired())
}

func (r *Runner) reassembleOutbound(raw []byte) (res reassembly.Result, err error) {
	if !packet.IsFragment(raw) {
		return reassembly.Result{Packet: raw, Ready: true}, nil
	}
	if len(raw) == 0 {
		return reassembly.Result{}, errors.New("empty fragment")
	}
	defer r.takeFragmentTimeouts(r.out4, r.out6)
	switch raw[0] >> 4 {
	case 4:
		return r.out4.PushInfo(raw)
	case 6:
		return r.out6.PushInfo(raw)
	default:
		return reassembly.Result{}, errors.New("fragment is not IPv4/IPv6")
	}
}

func (r *Runner) reassembleInbound(raw []byte) (res reassembly.Result, err error) {
	if !packet.IsFragment(raw) {
		return reassembly.Result{Packet: raw, Ready: true}, nil
	}
	if len(raw) == 0 {
		return reassembly.Result{}, errors.New("empty fragment")
	}
	defer r.takeFragmentTimeouts(r.in4, r.in6)
	switch raw[0] >> 4 {
	case 4:
		return r.in4.PushInfo(raw)
	case 6:
		return r.in6.PushInfo(raw)
	default:
		return reassembly.Result{}, errors.New("fragment is not IPv4/IPv6")
	}
}

func (r *Runner) reinjectDirect(raw []byte, addr windivert.Address, frag reassembly.Result) error {
	if !frag.Fragmented {
		if err := r.netHandle.Send(raw, addr); err != nil {
			return err
		}
		r.bypassed.Add(1)
		return nil
	}

	// Classification required full reassembly. Restore the original IP-level
	// shape before DIRECT reinjection so a large datagram is not injected below
	// the stack as one oversized packet. Transport checksum is computed on the
	// complete datagram before it is fragmented again.
	cp := append([]byte(nil), raw...)
	if err := windivert.CalcChecksums(cp); err != nil {
		return fmt.Errorf("checksum reassembled DIRECT datagram: %w", err)
	}
	mtu := frag.FragmentMTU
	if mtu <= 0 || mtu >= len(cp) {
		if err := r.netHandle.Send(cp, addr); err != nil {
			return err
		}
		r.bypassed.Add(1)
		return nil
	}
	parts, split, err := packet.FragmentForMTU(cp, mtu)
	if err != nil {
		return fmt.Errorf("DIRECT re-fragment: %w", err)
	}
	if split {
		r.fragRefragmented.Add(1)
	}
	for _, part := range parts {
		if err := r.netHandle.Send(part, addr); err != nil {
			return err
		}
		r.bypassed.Add(1)
	}
	return nil
}

func (r *Runner) prepareTunnelPackets(cp []byte, p packet.Packet) ([][]byte, bool, error) {
	if len(cp) <= r.cfg.MTU {
		if err := windivert.CalcChecksums(cp); err != nil {
			return nil, false, fmt.Errorf("checksum: %w", err)
		}
		return [][]byte{cp}, false, nil
	}

	if p.Protocol == packet.ProtoTCP {
		segments, split, err := packet.SplitForMTU(cp, r.cfg.MTU)
		if err != nil {
			return nil, false, err
		}
		for _, seg := range segments {
			if err := windivert.CalcChecksums(seg); err != nil {
				return nil, false, fmt.Errorf("segmented checksum: %w", err)
			}
		}
		return segments, split, nil
	}

	// UDP cannot be byte-sliced like TCP. Finalize its transport checksum on
	// the full NATed datagram, then use real IP fragmentation for WG inner MTU.
	if err := windivert.CalcChecksums(cp); err != nil {
		return nil, false, fmt.Errorf("oversize datagram checksum: %w", err)
	}
	parts, split, err := packet.FragmentForMTU(cp, r.cfg.MTU)
	if err != nil {
		return nil, false, err
	}
	if split {
		r.fragRefragmented.Add(1)
	}
	return parts, split, nil
}

func (r *Runner) captureLoop(ctx context.Context, urgentQ, bulkQ chan<- queuedPacket) {
	buf := make([]byte, windivert.MaxPacketSize)
	for {
		raw, addr, err := r.netHandle.Recv(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				r.log("packet capture error: %v", err)
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		r.captured.Add(1)
		frag, err := r.reassembleOutbound(raw)
		if err != nil {
			r.fragErrors.Add(1)
			r.dropped.Add(1)
			r.log("drop outbound fragment: %v", err)
			continue
		}
		if !frag.Ready {
			continue
		}
		if frag.Fragmented {
			r.fragReassembled.Add(1)
			raw = frag.Packet
		}
		p, err := packet.Parse(raw)
		if err != nil {
			if errors.Is(err, packet.ErrFragment) || frag.Fragmented {
				r.fragErrors.Add(1)
				r.dropped.Add(1)
				r.log("drop fragment that remained unparseable after reassembly: %v", err)
				continue
			}
			if e := r.netHandle.Send(raw, addr); e != nil {
				r.dropped.Add(1)
				r.log("unparsed bypass reinject failed: %v", e)
			} else {
				r.bypassed.Add(1)
			}
			continue
		}
		key := flow.Key{Proto: p.Protocol, Local: p.Src.Unmap(), Remote: p.Dst.Unmap(), LocalPort: p.SrcPort, RemotePort: p.DstPort}
		proxyTunnel, proxyKnown := r.proxyRoutes.Lookup(key)
		entry, sticky := r.routes.Lookup(key)
		var proc flow.Process
		var ok bool
		var d policy.Decision
		first := false
		switch {
		case proxyKnown:
			d = policy.Decision{Tunnel: proxyTunnel, Reason: "hostname-proxy"}
			r.routes.Set(key, proxyTunnel, flow.Process{}, true)
		case sticky:
			proc, ok = entry.proc, entry.known
			d = policy.Decision{Tunnel: entry.tunnel, Reason: "sticky-flow"}
		default:
			first = true
			proc, ok = r.flows.Lookup(key)
			needsProc := !r.policy.CouldTunnelWithoutProcess(p.Dst)
			if !ok && needsProc {
				proc, ok = r.flows.WaitLookup(key, 3*time.Millisecond)
			} // cheap SOCKET/FLOW event first
			if !ok && needsProc {
				proc, ok = r.flows.ResolveSocketOwner(key, windivert.ProcessInfo)
			} // expensive IP Helper only as fallback
			if ok {
				r.procResolved.Add(1)
			} else {
				r.procMissed.Add(1)
			}
			if ok && r.policy.IsInternal(proc) {
				d = policy.Decision{}
			} else {
				d = r.policy.Decide(proc, p.Dst)
			}
			r.routes.Set(key, d.Tunnel, proc, ok)
			if !ok && !d.Tunnel {
				r.stickyUnknownDirect.Add(1)
				r.log("flow attribution miss -> sticky DIRECT proto=%d %s:%d -> %s:%d", p.Protocol, p.Src, p.SrcPort, p.Dst, p.DstPort)
			}
		}
		needsHostname := !proxyKnown && ok && !r.policy.IsInternal(proc) && r.policy.NeedsTLSDiscovery(proc)
		tlsDiscover := needsHostname && p.Protocol == packet.ProtoTCP && p.DstPort == 443
		aggressive := r.aggressiveDiscovery.Load() && r.policy.ShouldSuppressQUIC(proc)
		quicDiscover := aggressive && !proxyKnown && ok && !r.policy.IsInternal(proc) && p.Protocol == packet.ProtoUDP && p.DstPort == 443
		if tlsDiscover || quicDiscover {
			r.discoveryPackets.Add(1)
		}
		if tlsDiscover && r.policy.IsDomainIPForProcess(proc, p.Dst) {
			r.domainMatches.Add(1)
		}
		if quicDiscover && !d.Tunnel && r.discovery.SuppressUnknownQUIC(p.Dst) {
			r.quicSuppressed.Add(1)
			r.dropped.Add(1)
			continue
		}
		if tlsDiscover && !d.Tunnel {
			name, res := r.discovery.FeedTLS(key, raw)
			if res == browserdisc.TLSClientHello && name != "" {
				groups := r.domains.AddForName(name, p.Dst, 30*time.Minute)
				if len(groups) > 0 && r.policy.DecideHost(proc, name).Tunnel {
					r.sniLearned.Add(1)
					r.log("TLS SNI matched %s -> learned %s; reconnecting matched flow", name, p.Dst.Unmap())
					if r.resetBrowserTCP(raw, addr, p) {
						r.reconnects.Add(1)
					}
					r.routes.Delete(key)
					continue
				}
			}
		}
		if !d.Tunnel {
			if e := r.reinjectDirect(raw, addr, frag); e != nil {
				r.dropped.Add(1)
				if frag.Fragmented {
					r.fragErrors.Add(1)
				}
				r.log("bypass reinject failed: %v", e)
			}
			continue
		}
		// An already-established TCP flow cannot migrate from DIRECT to a different
		// public address. Close it once; the replacement SYN is then routed sticky WG.
		if first && p.Protocol == packet.ProtoTCP && !packet.IsTCPSYN(raw) {
			if r.resetBrowserTCP(raw, addr, p) {
				r.preexistingTCPReset.Add(1)
			}
			r.routes.Delete(key)
			continue
		}
		cp := append([]byte(nil), raw...)
		m := addr.NetworkMeta()
		if _, err := r.nat.PrepareOutbound(cp, nat.Meta{IfIdx: m.IfIdx, SubIfIdx: m.SubIfIdx}); err != nil {
			r.dropped.Add(1)
			r.log("drop selected packet (%s): NAT: %v", d.Reason, err)
			continue
		}
		maxMSS := r.cfg.MTU - 40
		if p.Version == 6 {
			maxMSS = r.cfg.MTU - 60
		}
		if maxMSS > 500 && maxMSS < 65536 {
			_, _ = packet.ClampTCPMSS(cp, uint16(maxMSS))
		}
		segments, split, err := r.prepareTunnelPackets(cp, p)
		if err != nil {
			r.oversizeDropped.Add(1)
			r.dropped.Add(1)
			r.log("drop selected packet (%s): MTU/checksum: %v", d.Reason, err)
			continue
		}
		if split {
			r.oversizeSegmented.Add(1)
		}
		for _, seg := range segments {
			q := bulkQ
			if p.Protocol == packet.ProtoUDP {
				q = urgentQ
			}
			item := queuedPacket{raw: seg, queued: time.Now()}
			select {
			case q <- item:
				r.tunneled.Add(1)
				updateMax(&r.sendQueueHigh, uint64(len(q)))
			case <-ctx.Done():
				return
			default:
				r.dropped.Add(1)
				r.log("WireGuard %s queue full; selected packet dropped", map[bool]string{true: "urgent", false: "bulk"}[p.Protocol == packet.ProtoUDP])
			}
		}
	}
}

func (r *Runner) resetBrowserTCP(raw []byte, addr windivert.Address, p packet.Packet) bool {
	rst, err := packet.BuildTCPResetReply(raw)
	if err == nil {
		err = windivert.CalcChecksums(rst)
	}
	if err == nil {
		m := addr.NetworkMeta()
		err = r.netHandle.Send(rst, windivert.NewInboundAddress(windivert.NetworkMeta{IfIdx: m.IfIdx, SubIfIdx: m.SubIfIdx}, p.Version == 6))
	}
	if err != nil {
		r.log("TCP reconnect RST failed: %v", err)
		r.dropped.Add(1)
		return false
	}
	return true
}

func (r *Runner) sendOne(ctx context.Context, p queuedPacket) {
	delay := time.Since(p.queued)
	if delay > 0 {
		updateMax(&r.sendQueueDelayMaxMS, uint64(delay.Milliseconds()))
	}
	sendCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	err := r.wg.SendPacket(sendCtx, p.raw)
	cancel()
	if err != nil {
		r.wgWriteErrors.Add(1)
		r.dropped.Add(1)
		r.log("WireGuard send failed: %v", err)
	} else {
		r.wgWriteOK.Add(1)
	}
}
func (r *Runner) sendLoop(ctx context.Context, urgentQ, bulkQ <-chan queuedPacket) {
	const urgentBurst = 8
	for {
		// Give latency-sensitive UDP priority, but cap the burst so a continuous
		// Discord/voice stream cannot starve bulk TCP forever.
		drained := 0
		for drained < urgentBurst {
			select {
			case p := <-urgentQ:
				r.sendOne(ctx, p)
				drained++
			case <-ctx.Done():
				return
			default:
				drained = urgentBurst
			}
		}

		// After each urgent burst, force one ready bulk packet before returning
		// to priority mode. If bulk is empty, wait for either class normally.
		select {
		case p := <-bulkQ:
			r.sendOne(ctx, p)
			continue
		default:
		}
		select {
		case p := <-urgentQ:
			r.sendOne(ctx, p)
		case p := <-bulkQ:
			r.sendOne(ctx, p)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) wgReceiveLoop(ctx context.Context) {
	for {
		select {
		case raw := <-r.wg.Packets():
			if len(raw) == 0 {
				continue
			}
			frag, err := r.reassembleInbound(raw)
			if err != nil {
				r.fragErrors.Add(1)
				r.inboundErrors.Add(1)
				r.dropped.Add(1)
				r.log("inbound fragment reassembly: %v", err)
				continue
			}
			if !frag.Ready {
				continue
			}
			if frag.Fragmented {
				r.fragReassembled.Add(1)
			}
			cp := append([]byte(nil), frag.Packet...)
			if pre, preErr := packet.Parse(cp); preErr == nil && pre.Protocol != packet.ProtoTCP && pre.Protocol != packet.ProtoUDP {
				r.inboundOther.Add(1)
			}
			meta, ok, err := r.nat.RestoreInbound(cp)
			if err != nil {
				r.inboundErrors.Add(1)
				r.dropped.Add(1)
				r.log("reverse NAT: %v", err)
				continue
			}
			if !ok {
				r.reverseNATMiss.Add(1)
				r.dropped.Add(1)
				continue
			}
			p, err := packet.Parse(cp)
			if err != nil {
				r.inboundErrors.Add(1)
				r.dropped.Add(1)
				if errors.Is(err, packet.ErrFragment) || frag.Fragmented {
					r.fragErrors.Add(1)
				}
				r.log("inbound parse after NAT: %v", err)
				continue
			}
			maxMSS := r.cfg.MTU - 40
			if p.Version == 6 {
				maxMSS = r.cfg.MTU - 60
			}
			if maxMSS > 500 && maxMSS < 65536 {
				_, _ = packet.ClampTCPMSS(cp, uint16(maxMSS))
			}
			// Recalculate transport checksum on the restored complete datagram. If
			// it arrived fragmented, fragment again only after checksum/NAT.
			if err := windivert.CalcChecksums(cp); err != nil {
				r.inboundErrors.Add(1)
				r.dropped.Add(1)
				r.log("inbound checksum: %v", err)
				continue
			}
			parts := [][]byte{cp}
			if frag.Fragmented && frag.FragmentMTU > 0 && len(cp) > frag.FragmentMTU {
				var split bool
				parts, split, err = packet.FragmentForMTU(cp, frag.FragmentMTU)
				if err != nil {
					r.fragErrors.Add(1)
					r.inboundErrors.Add(1)
					r.dropped.Add(1)
					r.log("inbound re-fragment: %v", err)
					continue
				}
				if split {
					r.fragRefragmented.Add(1)
				}
			}
			a := windivert.NewInboundAddress(windivert.NetworkMeta{IfIdx: meta.IfIdx, SubIfIdx: meta.SubIfIdx}, p.Version == 6)
			failed := false
			for _, part := range parts {
				if err := r.netHandle.Send(part, a); err != nil {
					r.inboundErrors.Add(1)
					r.dropped.Add(1)
					r.log("inbound inject failed: %v", err)
					failed = true
					break
				}
				r.inboundInjected.Add(1)
			}
			if failed {
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) flowLoop(ctx context.Context) {
	for {
		ev, err := r.flowHandle.RecvFlow()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				r.log("flow capture error: %v", err)
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		switch ev.Event {
		case windivert.EventFlowEstablished:
			r.flows.Add(ev.Key, ev.Process)
		case windivert.EventFlowDeleted:
			r.flows.Delete(ev.Key)
			r.routes.Delete(ev.Key)
			r.discovery.DeleteFlow(ev.Key)
			r.proxyRoutes.DeleteFlow(ev.Key)
		}
	}
}
func (r *Runner) socketLoop(ctx context.Context) {
	for {
		ev, err := r.socketHandle.RecvSocket()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				r.log("socket capture error: %v", err)
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		k := ev.Key
		switch ev.Event {
		case windivert.EventSocketBind, windivert.EventSocketConnect, windivert.EventSocketListen, windivert.EventSocketAccept:
			// SOCKET owns only the local endpoint and is keyed by EndpointId.
			// Exact 5-tuples belong to FLOW (or one-shot IP Helper fallback), so
			// a delayed SOCKET_CLOSE cannot leave or erase stale flow ownership.
			r.flows.AddSocket(ev.EndpointID, k.Proto, k.Local, k.LocalPort, ev.Process)
		case windivert.EventSocketClose:
			r.flows.DeleteSocket(ev.EndpointID)
		}
	}
}
func (r *Runner) dnsLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		raw, _, err := r.dnsHandle.Recv(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		p, err := packet.Parse(raw)
		if err != nil || p.Protocol != packet.ProtoUDP || p.L4+8 > len(raw) {
			continue
		}
		res, err := domain.ParseDNSResponse(raw[p.L4+8:p.Total], r.domains.NameMatches)
		if err != nil {
			continue
		}
		groups := r.domains.GroupsForNames(res.Names)
		for _, ip := range res.IPs {
			r.domains.AddGroups(ip, groups, res.TTL)
		}
	}
}
func (r *Runner) bootstrapLoop(ctx context.Context) {
	run := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		r.domains.ResolveBootstrapWithResolver(c, 5*time.Minute, r.dnsResolver)
		cancel()
	}
	run()
	t := time.NewTicker(time.Duration(r.cfg.DNSRefreshSeconds) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			run()
		case <-ctx.Done():
			return
		}
	}
}
func (r *Runner) maintenanceLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.flows.Sweep(30 * time.Minute)
			r.routes.Sweep(30 * time.Minute)
			r.nat.Sweep(15 * time.Minute)
			r.domains.Sweep()
			r.discovery.Sweep()
			r.proxyRoutes.Sweep(30 * time.Minute)
			r.out4.Sweep()
			r.in4.Sweep()
			r.out6.Sweep()
			r.in6.Sweep()
			r.takeFragmentTimeouts(r.out4, r.out6)
			r.takeFragmentTimeouts(r.in4, r.in6)
		case <-ctx.Done():
			return
		}
	}
}
func (r *Runner) socketSnapshotLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if _, _, err := r.flows.SnapshotExisting(windivert.ProcessInfo); err != nil {
				r.log("socket ownership refresh partially failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}
func (r *Runner) diagnosticLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s := r.Status()
			r.log("[diag] cap=%d tunnel=%d direct=%d drop=%d procMiss=%d stickyMiss=%d preTCP=%d seg=%d oversizeDrop=%d qHigh=%d qDelayMax=%dms wgWrite=%d/%d rawRX=%d noSession=%d auth=%d replay=%d invalidInner=%d plainQHigh=%d plainDrop=%d frag=%d/%d/%d timeout=%d natMiss=%d otherIn=%d inbound=%d/%d", s.Captured, s.Tunneled, s.Bypassed, s.Dropped, s.ProcessMissed, s.StickyUnknownDirect, s.PreexistingTCPReset, s.OversizeSegmented, s.OversizeDropped, s.SendQueueHigh, s.SendQueueDelayMaxMS, s.WGWriteOK, s.WGWriteErrors, s.WGRawRX, s.WGNoSession, s.WGAuthFail, s.WGReplayDrop, s.WGInvalidInner, s.WGPlainQHigh, s.WGPlainDrop, s.FragReassembled, s.FragRefragmented, s.FragErrors, s.FragTimeouts, s.ReverseNATMiss, s.InboundOther, s.InboundInjected, s.InboundErrors)
		case <-ctx.Done():
			return
		}
	}
}
