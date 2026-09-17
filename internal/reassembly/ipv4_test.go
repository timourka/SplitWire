package reassembly

import (
	"encoding/binary"
	"testing"
)

func frag(id uint16, off int, more bool, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	copy(b[12:16], []byte{10, 0, 0, 2})
	copy(b[16:20], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], id)
	f := uint16(off / 8)
	if more {
		f |= 0x2000
	}
	binary.BigEndian.PutUint16(b[6:8], f)
	copy(b[20:], payload)
	return b
}
func TestIPv4Reassembly(t *testing.T) {
	r := NewIPv4()
	p1 := make([]byte, 16)
	binary.BigEndian.PutUint16(p1[0:2], 53)
	binary.BigEndian.PutUint16(p1[2:4], 50000)
	copy(p1[8:], []byte("abcdefgh"))
	p2 := []byte("ijklmnop")
	if _, ready, err := r.Push(frag(7, 16, false, p2)); err != nil || ready {
		t.Fatalf("second first: ready=%v err=%v", ready, err)
	}
	out, ready, err := r.Push(frag(7, 0, true, p1))
	if err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	if len(out) != 20+24 || binary.BigEndian.Uint16(out[6:8])&0x3fff != 0 {
		t.Fatalf("bad result len=%d frag=%x", len(out), binary.BigEndian.Uint16(out[6:8]))
	}
	if string(out[len(out)-8:]) != "ijklmnop" {
		t.Fatalf("payload=%q", out[20:])
	}
}

func TestIPv4ExpiredCount(t *testing.T) {
	r := NewIPv4()
	r.ttl = -1
	if _, ready, err := r.Push(frag(99, 0, true, []byte("12345678"))); err != nil || ready {
		t.Fatalf("first fragment: ready=%v err=%v", ready, err)
	}
	// PushInfo sweeps old entries before adding the next fragment.
	if _, ready, err := r.Push(frag(100, 0, true, []byte("abcdefgh"))); err != nil || ready {
		t.Fatalf("second fragment: ready=%v err=%v", ready, err)
	}
	if got := r.TakeExpired(); got == 0 {
		t.Fatal("expected expired reassembly count")
	}
	if got := r.TakeExpired(); got != 0 {
		t.Fatalf("TakeExpired must clear counter, got %d", got)
	}
}
