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

func TestSnapshotLocalEndpointFallback(t *testing.T) {
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

func TestSocketWildcardBindMatchesConcreteLocalAddress(t *testing.T) {
	i := New()
	i.AddSocket(100, 17, netip.MustParseAddr("0.0.0.0"), 60000, Process{PID: 42, Name: "Discord.exe"})
	p, ok := i.Lookup(Key{Proto: 17, Local: netip.MustParseAddr("10.0.0.50"), Remote: netip.MustParseAddr("9.9.9.9"), LocalPort: 60000, RemotePort: 50000})
	if !ok || p.PID != 42 {
		t.Fatalf("got=%+v ok=%v", p, ok)
	}
}

func TestFlowDeleteDoesNotDeleteSocketOwnership(t *testing.T) {
	i := New()
	k := Key{Proto: 17, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 1234, RemotePort: 443}
	i.AddSocket(7, k.Proto, k.Local, k.LocalPort, Process{PID: 10, Name: "Discord.exe"})
	i.Add(k, Process{PID: 10, Name: "Discord.exe"})
	i.Delete(k)
	if p, ok := i.Lookup(k); !ok || p.PID != 10 {
		t.Fatalf("socket ownership disappeared: %+v %v", p, ok)
	}
	i.DeleteSocket(7)
	if _, ok := i.Lookup(k); ok {
		t.Fatal("SOCKET close must remove live local ownership")
	}
}

func TestLateCloseCannotDeleteReusedPort(t *testing.T) {
	i := New()
	local := netip.MustParseAddr("10.0.0.10")
	key := Key{Proto: 17, Local: local, Remote: netip.MustParseAddr("203.0.113.1"), LocalPort: 50000, RemotePort: 3478}
	i.AddSocket(100, 17, local, 50000, Process{PID: 1, Name: "old.exe"})
	time.Sleep(time.Millisecond)
	i.AddSocket(200, 17, local, 50000, Process{PID: 2, Name: "new.exe"})
	i.DeleteSocket(100) // delayed close for the old endpoint
	p, ok := i.Lookup(key)
	if !ok || p.PID != 2 {
		t.Fatalf("reused endpoint lost: %+v ok=%v", p, ok)
	}
	i.DeleteSocket(200)
	if _, ok := i.Lookup(key); ok {
		t.Fatal("new endpoint survived its own close")
	}
}

func TestExactFlowDoesNotCreatePersistentLocalFallback(t *testing.T) {
	i := New()
	k := Key{Proto: 6, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 1234, RemotePort: 443}
	i.Add(k, Process{Name: "chrome.exe"})
	i.Delete(k)
	if _, ok := i.Lookup(k); ok {
		t.Fatal("FLOW ownership leaked into local-port fallback")
	}
}

func TestLiveSocketOverridesStaleSnapshotExactOnPortReuse(t *testing.T) {
	i := New()
	k := Key{Proto: 6, Local: netip.MustParseAddr("10.0.0.5"), Remote: netip.MustParseAddr("198.51.100.7"), LocalPort: 51000, RemotePort: 443}
	i.AddSnapshotExact(k, Process{PID: 1, Name: "old.exe"})
	i.AddSocket(200, 6, k.Local, k.LocalPort, Process{PID: 2, Name: "new.exe"})
	p, ok := i.Lookup(k)
	if !ok || p.PID != 2 {
		t.Fatalf("stale snapshot shadowed live socket: %+v ok=%v", p, ok)
	}
}
