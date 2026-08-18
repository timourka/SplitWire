package engine

import (
	"net/netip"
	"sync"
	"time"

	"splitwire/internal/flow"
)

type proxyRouteKey struct {
	Proto      uint8
	LocalPort  uint16
	Remote     netip.Addr
	RemotePort uint16
}

type proxyRouteEntry struct {
	tunnel bool
	seen   time.Time
}

type proxyRouteTable struct {
	mu sync.Mutex
	m  map[proxyRouteKey]proxyRouteEntry
}

func newProxyRouteTable() *proxyRouteTable {
	return &proxyRouteTable{m: map[proxyRouteKey]proxyRouteEntry{}}
}

func proxyKeyFromFlow(k flow.Key) proxyRouteKey {
	return proxyRouteKey{Proto: k.Proto, LocalPort: k.LocalPort, Remote: k.Remote.Unmap(), RemotePort: k.RemotePort}
}

func (t *proxyRouteTable) Set(k proxyRouteKey, tunnel bool) {
	if k.Proto == 0 || k.LocalPort == 0 || !k.Remote.IsValid() || k.RemotePort == 0 {
		return
	}
	k.Remote = k.Remote.Unmap()
	t.mu.Lock()
	t.m[k] = proxyRouteEntry{tunnel: tunnel, seen: time.Now()}
	t.mu.Unlock()
}

func (t *proxyRouteTable) Lookup(k flow.Key) (tunnel, ok bool) {
	pk := proxyKeyFromFlow(k)
	t.mu.Lock()
	e, ok := t.m[pk]
	if ok {
		e.seen = time.Now()
		t.m[pk] = e
	}
	t.mu.Unlock()
	return e.tunnel, ok
}

func (t *proxyRouteTable) DeleteFlow(k flow.Key) {
	pk := proxyKeyFromFlow(k)
	t.mu.Lock()
	delete(t.m, pk)
	t.mu.Unlock()
}

func (t *proxyRouteTable) DeleteKey(k proxyRouteKey) {
	k.Remote = k.Remote.Unmap()
	t.mu.Lock()
	delete(t.m, k)
	t.mu.Unlock()
}

func (t *proxyRouteTable) Sweep(age time.Duration) {
	cut := time.Now().Add(-age)
	t.mu.Lock()
	for k, e := range t.m {
		if e.seen.Before(cut) {
			delete(t.m, k)
		}
	}
	t.mu.Unlock()
}
