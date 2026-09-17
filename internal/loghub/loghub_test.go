package loghub

import (
	"bytes"
	"testing"
)

func TestHubFanout(t *testing.T) {
	var a, b bytes.Buffer
	h := New(&a, &b)
	if _, err := h.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if a.String() != "hello\n" || b.String() != "hello\n" {
		t.Fatalf("fanout mismatch: %q %q", a.String(), b.String())
	}
}

func TestRingBounded(t *testing.T) {
	r := NewRing(4096)
	p := bytes.Repeat([]byte{'x'}, 5000)
	_, _ = r.Write(p)
	if got := len(r.Snapshot()); got != 4096 {
		t.Fatalf("got %d", got)
	}
}

func TestRingNotificationCoalescesAndRearms(t *testing.T) {
	r := NewRing(4096)
	n := 0
	r.SetNotify(func() { n++ })
	_, _ = r.Write([]byte("a"))
	_, _ = r.Write([]byte("b"))
	if n != 1 {
		t.Fatalf("notifications=%d", n)
	}
	d := r.DrainAndAck()
	if d.Replace || d.Text != "ab" {
		t.Fatalf("drain=%+v", d)
	}
	_, _ = r.Write([]byte("c"))
	if n != 2 {
		t.Fatalf("notifications after rearm=%d", n)
	}
	r.Clear()
	if r.Snapshot() != "" {
		t.Fatal("clear failed")
	}
}

func TestRingSeedThenIncrementalDrain(t *testing.T) {
	r := NewRing(4096)
	r.Seed([]byte("history\n"))
	d := r.DrainAndAck()
	if !d.Replace || d.Text != "history\n" {
		t.Fatalf("seed drain=%+v", d)
	}
	_, _ = r.Write([]byte("new\n"))
	d = r.DrainAndAck()
	if d.Replace || d.Text != "new\n" {
		t.Fatalf("delta drain=%+v", d)
	}
}

func TestRingLagForcesFullResync(t *testing.T) {
	r := NewRing(4096)
	_, _ = r.Write(bytes.Repeat([]byte{'a'}, 3000))
	_, _ = r.Write(bytes.Repeat([]byte{'b'}, 3000))
	d := r.DrainAndAck()
	if !d.Replace || len(d.Text) != 4096 {
		t.Fatalf("expected bounded full resync, got replace=%v len=%d", d.Replace, len(d.Text))
	}
}
