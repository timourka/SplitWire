package nat

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"splitwire/internal/packet"
)

func udp4(src, dst [4]byte, sp, dp uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[20:22], sp)
	binary.BigEndian.PutUint16(b[22:24], dp)
	binary.BigEndian.PutUint16(b[24:26], 8)
	return b
}
func TestRoundTrip(t *testing.T) {
	m := New(netip.MustParseAddr("10.66.66.20"), netip.Addr{})
	out := udp4([4]byte{192, 168, 0, 101}, [4]byte{203, 0, 113, 9}, 54321, 443)
	meta := Meta{IfIdx: 18, SubIfIdx: 0}
	if _, err := m.PrepareOutbound(out, meta); err != nil {
		t.Fatal(err)
	}
	p, err := packet.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if p.Src.String() != "10.66.66.20" {
		t.Fatalf("src=%v", p.Src)
	}
	reply := udp4([4]byte{203, 0, 113, 9}, [4]byte{10, 66, 66, 20}, 443, p.SrcPort)
	gotMeta, ok, err := m.RestoreInbound(reply)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	rp, _ := packet.Parse(reply)
	if rp.Dst.String() != "192.168.0.101" || rp.DstPort != 54321 {
		t.Fatalf("restored %v:%d", rp.Dst, rp.DstPort)
	}
	if gotMeta != meta {
		t.Fatalf("meta=%+v", gotMeta)
	}
}
