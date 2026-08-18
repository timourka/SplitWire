//go:build windows

package engine

import (
	"context"
	"net"
	"net/netip"
	"time"

	"splitwire/internal/flow"
	"splitwire/internal/windivert"
)

// AuthorizeProxyClient resolves the process that opened the loopback
// connection to SplitWire's hostname proxy and applies the same group engine to
// the original process + hostname pair.
func (r *Runner) AuthorizeProxyClient(clientAddr, proxyAddr, host string) (bool, string) {
	client, err1 := netip.ParseAddrPort(clientAddr)
	proxy, err2 := netip.ParseAddrPort(proxyAddr)
	if err1 != nil || err2 != nil {
		// Apps=* groups are safe without process identity.
		d := r.policy.DecideHost(flow.Process{}, host)
		if d.Tunnel {
			r.proxyTunnel.Add(1)
			return true, d.Reason + "/global"
		}
		r.proxyDirect.Add(1)
		return false, "client-address-unresolved"
	}
	key := flow.Key{Proto: 6, Local: client.Addr().Unmap(), Remote: proxy.Addr().Unmap(), LocalPort: client.Port(), RemotePort: proxy.Port()}
	proc, ok := r.flows.Lookup(key)
	if !ok {
		proc, ok = r.flows.ResolveSocketOwner(key, windivert.ProcessInfo)
	}
	if !ok {
		proc, ok = r.flows.WaitLookup(key, 25*time.Millisecond)
	}
	if !ok {
		proc, ok = r.flows.ResolveSocketOwner(key, windivert.ProcessInfo)
	}
	if !ok {
		d := r.policy.DecideHost(flow.Process{}, host)
		if d.Tunnel {
			r.proxyTunnel.Add(1)
			return true, d.Reason + "/global"
		}
		r.proxyDirect.Add(1)
		return false, "client-process-unresolved"
	}
	d := r.policy.DecideHost(proc, host)
	if d.Tunnel {
		r.proxyTunnel.Add(1)
		return true, proc.Name + "/" + d.Group
	}
	r.proxyDirect.Add(1)
	return false, proc.Name + "/no-matching-group"
}

// DialProxy opens an upstream proxy socket with an explicit WireGuard/DIRECT
// route decision registered before the first SYN is emitted.
func (r *Runner) DialProxy(ctx context.Context, network, address string, tunnel bool) (net.Conn, error) {
	return dialProxyRegistered(ctx, network, address, tunnel, r.proxyRoutes)
}
