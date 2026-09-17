package engine

import (
	"net/netip"
	"splitwire/internal/flow"
	"testing"
)

func TestFlowRouteSticky(t *testing.T) {
	tab := newFlowRouteTable()
	k := flow.Key{Proto: 6, Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("198.51.100.1"), LocalPort: 50000, RemotePort: 443}
	tab.Set(k, true, flow.Process{Name: "Discord.exe"}, true)
	tab.Set(k, false, flow.Process{}, false)
	e, ok := tab.Lookup(k)
	if !ok || !e.tunnel || !e.known {
		t.Fatalf("not sticky: %+v %v", e, ok)
	}
	tab.Delete(k)
	if _, ok := tab.Lookup(k); ok {
		t.Fatal("delete failed")
	}
}
