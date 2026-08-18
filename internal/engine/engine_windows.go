//go:build windows

package engine

import (
	"context"
	"fmt"
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
	"splitwire/internal/windivert"
	"splitwire/internal/wireguard"
)

type Logf func(string, ...any)

type Status struct {
	Captured         uint64
	Tunneled         uint64
	Bypassed         uint64
	Dropped          uint64
	WGTxBytes        uint64
	WGRxBytes        uint64
	DomainIPs        int
	LastHandshake    time.Time
	ProcessResolved  uint64
	ProcessMissed    uint64
	DiscoveryPackets uint64
	DomainMatches    uint64
	SNILearned       uint64
	QUICSuppressed   uint64
	Reconnects       uint64
	ProxyTunnel      uint64
	ProxyDirect      uint64
}

type Runner struct {
	cfg        *config.Config
	ifaceIndex uint32
	ifaceName  string
	logf       Logf

	flows       *flow.Index
	domains     *domain.Tracker
	discovery   *browserdisc.Discovery
	policy      *policy.Engine
	proxyRoutes *proxyRouteTable
	nat         *nat.Mapper
	wg          *wireguard.Client
	netHandle   *windivert.Handle
	flowHandle  *windivert.Handle
	dnsHandle   *windivert.Handle

	cancel    context.CancelFunc
	wgDone    sync.WaitGroup
	closeOnce sync.Once

	captured         atomic.Uint64
	tunneled         atomic.Uint64
	bypassed         atomic.Uint64
	dropped          atomic.Uint64
	procResolved     atomic.Uint64
	procMissed       atomic.Uint64
	discoveryPackets atomic.Uint64
	domainMatches    atomic.Uint64
	sniLearned       atomic.Uint64
	quicSuppressed   atomic.Uint64
	reconnects       atomic.Uint64
	proxyTunnel      atomic.Uint64
	proxyDirect      atomic.Uint64
}

type Params struct {
	Config            *config.Config
	InterfaceIndex    uint32
	InterfaceName     string
	InternalProcesses []string
	Logf              Logf
}

type queuedPacket struct{ raw []byte }

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
			wg.Close()
		}
	}()

	// Exclude the outer WireGuard UDP source port from interception to prevent
	// recursive capture. TCP is always captured.
	filter := fmt.Sprintf("outbound and !loopback and !impostor and (tcp or (udp and udp.SrcPort != %d))", wg.LocalPort())
	nh, err := windivert.OpenNetwork(filter, 0, 0)
	if err != nil {
		return nil, err
	}
	cleanupN := true
	defer func() {
		if cleanupN {
			nh.Close()
		}
	}()
	fh, err := windivert.OpenFlow("true", 100)
	if err != nil {
		return nil, err
	}
	cleanupF := true
	defer func() {
		if cleanupF {
			fh.Close()
		}
	}()
	dh, err := windivert.OpenNetwork("inbound and udp and udp.SrcPort == 53", -100, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		return nil, err
	}
	cleanupD := true
	defer func() {
		if cleanupD {
			dh.Close()
		}
	}()

	tr := domain.New(p.Config.Groups)
	v4, _ := p.Config.TunnelIPv4()
	v6, _ := p.Config.TunnelIPv6()
	ctx, cancel := context.WithCancel(parent)
	r := &Runner{cfg: p.Config, ifaceIndex: p.InterfaceIndex, ifaceName: p.InterfaceName, logf: p.Logf, flows: flow.New(), domains: tr, discovery: browserdisc.New(), proxyRoutes: newProxyRouteTable(), nat: nat.New(v4, v6), wg: wg, netHandle: nh, flowHandle: fh, dnsHandle: dh, cancel: cancel}
	r.policy = policy.NewWithInternal(p.Config, tr, p.InternalProcesses)

	// Seed known ChatGPT/OpenAI endpoints before diverting browser traffic.
	seedCtx, seedCancel := context.WithTimeout(ctx, 5*time.Second)
	tr.ResolveBootstrap(seedCtx, 5*time.Minute)
	seedCancel()

	// WinDivert FLOW events only describe flows created after a FLOW handle is
	// active. Import the current Windows socket ownership table as well so
	// Discord/Chrome connections that already existed when SplitWire started are
	// classified immediately instead of having to reconnect first.
	if tcpN, udpN, snapErr := r.flows.SnapshotExisting(windivert.ProcessInfo); snapErr != nil {
		r.log("initial socket ownership snapshot partially failed: %v", snapErr)
	} else {
		r.log("imported existing socket ownership: TCP=%d UDP=%d", tcpN, udpN)
	}

	sendQ := make(chan queuedPacket, 8192)
	r.goRun(func() { r.flowLoop(ctx) })
	r.goRun(func() { r.dnsLoop(ctx) })
	r.goRun(func() { r.bootstrapLoop(ctx) })
	r.goRun(func() { r.wgReceiveLoop(ctx) })
	r.goRun(func() { r.sendLoop(ctx, sendQ) })
	r.goRun(func() { r.maintenanceLoop(ctx) })
	r.goRun(func() { r.socketSnapshotLoop(ctx) })
	r.goRun(func() { r.captureLoop(ctx, sendQ) })

	cleanupWG = false
	cleanupN = false
	cleanupF = false
	cleanupD = false
	r.log("started on physical interface %s (%d), outer UDP port %d", p.InterfaceName, p.InterfaceIndex, wg.LocalPort())
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
		r.netHandle.Close()
		r.flowHandle.Close()
		r.dnsHandle.Close()
		r.wgDone.Wait()
		r.wg.Close()
		r.log("stopped")
	})
}

func (r *Runner) Status() Status {
	tx, rx := r.wg.Stats()
	return Status{Captured: r.captured.Load(), Tunneled: r.tunneled.Load(), Bypassed: r.bypassed.Load(), Dropped: r.dropped.Load(), WGTxBytes: tx, WGRxBytes: rx, DomainIPs: r.domains.Count(), LastHandshake: r.wg.LastHandshake(), ProcessResolved: r.procResolved.Load(), ProcessMissed: r.procMissed.Load(), DiscoveryPackets: r.discoveryPackets.Load(), DomainMatches: r.domainMatches.Load(), SNILearned: r.sniLearned.Load(), QUICSuppressed: r.quicSuppressed.Load(), Reconnects: r.reconnects.Load(), ProxyTunnel: r.proxyTunnel.Load(), ProxyDirect: r.proxyDirect.Load()}
}
func (r *Runner) Interface() string { return fmt.Sprintf("%s (%d)", r.ifaceName, r.ifaceIndex) }

func (r *Runner) captureLoop(ctx context.Context, sendQ chan<- queuedPacket) {
	buf := make([]byte, 65535)
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
		p, err := packet.Parse(raw)
		if err != nil {
			if e := r.netHandle.Send(raw, addr); e != nil {
				r.dropped.Add(1)
			} else {
				r.bypassed.Add(1)
			}
			continue
		}
		key := flow.Key{Proto: p.Protocol, Local: p.Src.Unmap(), Remote: p.Dst.Unmap(), LocalPort: p.SrcPort, RemotePort: p.DstPort}

		// Hostname-proxy sockets are registered before connect(), so their first
		// SYN can be classified without waiting for FLOW/PID attribution.
		proxyTunnel, proxyKnown := r.proxyRoutes.Lookup(key)
		var proc flow.Process
		var ok bool
		if !proxyKnown {
			proc, ok = r.flows.Lookup(key)
			if !ok {
				proc, ok = r.flows.ResolveSocketOwner(key, windivert.ProcessInfo)
			}
			if !ok && !r.policy.CouldTunnelWithoutProcess(p.Dst) {
				proc, ok = r.flows.WaitLookup(key, 12*time.Millisecond)
				if !ok {
					proc, ok = r.flows.ResolveSocketOwner(key, windivert.ProcessInfo)
				}
			}
			if ok {
				r.procResolved.Add(1)
			} else {
				r.procMissed.Add(1)
			}
		}

		var d policy.Decision
		switch {
		case proxyKnown:
			d = policy.Decision{Tunnel: proxyTunnel, Reason: "hostname-proxy"}
		case ok && r.policy.IsInternal(proc):
			// SplitWire's helper sockets are direct unless the hostname proxy
			// explicitly registered the socket above. This avoids accidentally
			// tunnelling DNS/logging/helper traffic because of a global group.
			d = policy.Decision{}
		default:
			d = r.policy.Decide(proc, p.Dst)
		}

		discover := !proxyKnown && ok && !r.policy.IsInternal(proc) && r.policy.NeedsTLSDiscovery(proc)
		if discover {
			r.discoveryPackets.Add(1)
			if r.policy.IsDomainIPForProcess(proc, p.Dst) {
				r.domainMatches.Add(1)
			}
		}

		// For explicitly named applications only, briefly suppress unknown QUIC
		// so TCP/TLS SNI can classify the hostname. Global Apps=* groups never
		// trigger this, otherwise every process would lose first UDP/443 packets.
		if discover && !d.Tunnel && r.policy.ShouldSuppressQUIC(proc) && p.Protocol == packet.ProtoUDP && p.DstPort == 443 {
			if r.discovery.SuppressUnknownQUIC(p.Dst) {
				r.quicSuppressed.Add(1)
				continue
			}
		}

		if discover && !d.Tunnel && p.Protocol == packet.ProtoTCP && p.DstPort == 443 {
			name, tlsResult := r.discovery.FeedTLS(key, raw)
			if tlsResult == browserdisc.TLSClientHello && name != "" {
				groups := r.domains.AddForName(name, p.Dst, 30*time.Minute)
				if len(groups) > 0 && r.policy.DecideHost(proc, name).Tunnel {
					r.sniLearned.Add(1)
					r.log("TLS SNI matched %s -> learned %s; reconnecting flow through WireGuard", name, p.Dst.Unmap())
					if r.resetBrowserTCP(raw, addr, p) {
						r.reconnects.Add(1)
					}
					continue
				}
			}
			if tlsResult == browserdisc.TLSNotClientHello && r.policy.ShouldSuppressQUIC(proc) && r.discovery.MarkReset(key) {
				// Explicit app/domain groups get one reconnect attempt for TLS flows
				// that predate SplitWire. Global groups intentionally do not reset all
				// existing HTTPS connections on the machine.
				r.log("restarting pre-existing TLS flow %s:%d -> %s:%d for hostname discovery", p.Src, p.SrcPort, p.Dst, p.DstPort)
				if r.resetBrowserTCP(raw, addr, p) {
					r.reconnects.Add(1)
				}
				continue
			}
		}

		if !d.Tunnel {
			if e := r.netHandle.Send(raw, addr); e != nil {
				r.dropped.Add(1)
				r.log("bypass reinject failed: %v", e)
			} else {
				r.bypassed.Add(1)
			}
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
		if err := windivert.CalcChecksums(cp); err != nil {
			r.dropped.Add(1)
			r.log("drop selected packet: checksum: %v", err)
			continue
		}
		select {
		case sendQ <- queuedPacket{cp}:
			r.tunneled.Add(1)
		case <-ctx.Done():
			return
		default:
			r.dropped.Add(1)
			r.log("WireGuard queue full; selected packet dropped")
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
		r.log("browser reconnect RST failed: %v", err)
		r.dropped.Add(1)
		return false
	}
	return true
}

func (r *Runner) sendLoop(ctx context.Context, q <-chan queuedPacket) {
	for {
		select {
		case p := <-q:
			sendCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := r.wg.SendPacket(sendCtx, p.raw)
			cancel()
			if err != nil {
				r.dropped.Add(1)
				r.log("WireGuard send failed: %v", err)
			}
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
			cp := append([]byte(nil), raw...)
			meta, ok, err := r.nat.RestoreInbound(cp)
			if err != nil {
				r.log("reverse NAT: %v", err)
				continue
			}
			if !ok {
				continue
			}
			if err := windivert.CalcChecksums(cp); err != nil {
				r.log("inbound checksum: %v", err)
				continue
			}
			p, err := packet.Parse(cp)
			if err != nil {
				continue
			}
			a := windivert.NewInboundAddress(windivert.NetworkMeta{IfIdx: meta.IfIdx, SubIfIdx: meta.SubIfIdx}, p.Version == 6)
			if err := r.netHandle.Send(cp, a); err != nil {
				r.dropped.Add(1)
				r.log("inbound inject failed: %v", err)
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
			r.discovery.DeleteFlow(ev.Key)
			r.proxyRoutes.DeleteFlow(ev.Key)
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
		payload := raw[p.L4+8 : p.Total]
		res, err := domain.ParseDNSResponse(payload, r.domains.NameMatches)
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
	d := time.Duration(r.cfg.DNSRefreshSeconds) * time.Second
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			r.domains.ResolveBootstrap(c, 5*time.Minute)
			cancel()
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
			r.nat.Sweep(15 * time.Minute)
			r.domains.Sweep()
			r.discovery.Sweep()
			r.proxyRoutes.Sweep(30 * time.Minute)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) socketSnapshotLoop(ctx context.Context) {
	// Refresh ownership for long-lived/pre-existing UDP sockets. FLOW events are
	// still the primary, exact source; this is a low-frequency safety net.
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
