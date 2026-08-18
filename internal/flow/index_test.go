package flow

import (
	"net/netip"
	"testing"
	"time"
)

func TestWait(t *testing.T) {
	i := New()
	k := Key{Proto: 17, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 1, RemotePort: 2}
	go func() { time.Sleep(time.Millisecond * 5); i.Add(k, Process{Name: "Discord.exe"}) }()
	p, ok := i.WaitLookup(k, time.Millisecond*50)
	if !ok || p.Name != "Discord.exe" {
		t.Fatal(p, ok)
	}
}

func TestLocalEndpointFallback(t *testing.T) {
	i := New()
	local := netip.MustParseAddr("192.168.1.10")
	i.AddLocal(17, local, 54321, Process{Name: "Discord.exe"})
	for _, remote := range []string{"1.1.1.1", "8.8.8.8"} {
		p, ok := i.Lookup(Key{Proto: 17, Local: local, Remote: netip.MustParseAddr(remote), LocalPort: 54321, RemotePort: 443})
		if !ok || p.Name != "Discord.exe" {
			t.Fatalf("remote=%s got=%+v ok=%v", remote, p, ok)
		}
	}
}

func TestWildcardLocalEndpointFallback(t *testing.T) {
	i := New()
	i.AddLocal(17, netip.Addr{}, 60000, Process{Name: "Discord.exe"})
	p, ok := i.Lookup(Key{Proto: 17, Local: netip.MustParseAddr("10.0.0.50"), Remote: netip.MustParseAddr("9.9.9.9"), LocalPort: 60000, RemotePort: 50000})
	if !ok || p.Name != "Discord.exe" {
		t.Fatalf("got=%+v ok=%v", p, ok)
	}
}

func TestDeleteRemovesExactLocalFallback(t *testing.T) {
	i := New()
	k := Key{Proto: 6, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 1234, RemotePort: 443}
	i.Add(k, Process{Name: "chrome.exe"})
	i.Delete(k)
	if _, ok := i.Lookup(k); ok {
		t.Fatal("deleted flow remained discoverable through local fallback")
	}
}
