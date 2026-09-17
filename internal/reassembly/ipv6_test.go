package reassembly

import (
	"encoding/binary"
	"testing"
)

func frag6(id uint32, off int, more bool, payload []byte) []byte {
	b := make([]byte, 40+8+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	b[6] = 44
	b[7] = 64
	b[8] = 0x20
	b[24] = 0x20
	b[40] = 17
	v := uint16((off / 8) << 3)
	if more {
		v |= 1
	}
	binary.BigEndian.PutUint16(b[42:44], v)
	binary.BigEndian.PutUint32(b[44:48], id)
	copy(b[48:], payload)
	return b
}

func TestIPv6Reassembly(t *testing.T) {
	r := NewIPv6()
	p1 := make([]byte, 16)
	binary.BigEndian.PutUint16(p1[0:2], 53)
	binary.BigEndian.PutUint16(p1[2:4], 50000)
	copy(p1[8:], []byte("abcdefgh"))
	p2 := []byte("ijklmnop")
	if res, err := r.PushInfo(frag6(77, 16, false, p2)); err != nil || res.Ready {
		t.Fatalf("second first: %+v err=%v", res, err)
	}
	res, err := r.PushInfo(frag6(77, 0, true, p1))
	if err != nil || !res.Ready || !res.Fragmented {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	out := res.Packet
	if len(out) != 40+24 || out[6] != 17 || binary.BigEndian.Uint16(out[4:6]) != 24 {
		t.Fatalf("bad result len=%d next=%d plen=%d", len(out), out[6], binary.BigEndian.Uint16(out[4:6]))
	}
	if string(out[len(out)-8:]) != "ijklmnop" {
		t.Fatalf("payload=%q", out[40:])
	}
}

func TestIPv6AtomicFragmentStripped(t *testing.T) {
	r := NewIPv6()
	res, err := r.PushInfo(frag6(99, 0, false, []byte("abcdefgh")))
	if err != nil || !res.Ready || !res.Fragmented {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(res.Packet) != 48 || res.Packet[6] != 17 {
		t.Fatalf("bad atomic result len=%d next=%d", len(res.Packet), res.Packet[6])
	}
}

func TestIPv6ExpiredCount(t *testing.T) {
	r := NewIPv6()
	r.ttl = -1
	if _, ready, err := r.Push(frag6(99, 0, true, []byte("12345678"))); err != nil || ready {
		t.Fatalf("first fragment: ready=%v err=%v", ready, err)
	}
	if _, ready, err := r.Push(frag6(100, 0, true, []byte("abcdefgh"))); err != nil || ready {
		t.Fatalf("second fragment: ready=%v err=%v", ready, err)
	}
	if got := r.TakeExpired(); got == 0 {
		t.Fatal("expected expired reassembly count")
	}
	if got := r.TakeExpired(); got != 0 {
		t.Fatalf("TakeExpired must clear counter, got %d", got)
	}
}
