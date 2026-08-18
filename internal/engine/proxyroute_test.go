package engine

import (
	"net/netip"
	"testing"

	"splitwire/internal/flow"
)

func TestProxyRouteTableExactFlow(t *testing.T) {
	tab := newProxyRouteTable()
	remote := netip.MustParseAddr("203.0.113.7")
	key := proxyRouteKey{Proto: 6, LocalPort: 50001, Remote: remote, RemotePort: 443}
	tab.Set(key, true)

	flowKey := flow.Key{Proto: 6, Local: netip.MustParseAddr("192.0.2.10"), Remote: remote, LocalPort: 50001, RemotePort: 443}
	if tunnel, ok := tab.Lookup(flowKey); !ok || !tunnel {
		t.Fatalf("expected registered tunnel route, got tunnel=%v ok=%v", tunnel, ok)
	}

	otherPort := flowKey
	otherPort.LocalPort++
	if _, ok := tab.Lookup(otherPort); ok {
		t.Fatal("route must be scoped to exact source port")
	}

	tab.DeleteFlow(flowKey)
	if _, ok := tab.Lookup(flowKey); ok {
		t.Fatal("flow deletion must remove proxy route")
	}
}

func TestProxyRouteTableDirectDecision(t *testing.T) {
	tab := newProxyRouteTable()
	remote := netip.MustParseAddr("198.51.100.8")
	tab.Set(proxyRouteKey{Proto: 6, LocalPort: 50100, Remote: remote, RemotePort: 443}, false)
	k := flow.Key{Proto: 6, Remote: remote, LocalPort: 50100, RemotePort: 443}
	if tunnel, ok := tab.Lookup(k); !ok || tunnel {
		t.Fatalf("expected explicit DIRECT route, got tunnel=%v ok=%v", tunnel, ok)
	}
}
