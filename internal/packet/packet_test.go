package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestIPv4Rewrite(t *testing.T) {
	b := make([]byte, 28)
	b[0] = 0x45
	b[2] = 0
	b[3] = 28
	b[9] = 17
	copy(b[12:16], []byte{192, 168, 0, 2})
	copy(b[16:20], []byte{1, 1, 1, 1})
	b[20] = 0x30
	b[21] = 0x39
	b[22] = 0
	b[23] = 53
	p, e := Parse(b)
	if e != nil || p.SrcPort != 12345 || p.DstPort != 53 {
		t.Fatalf("%+v %v", p, e)
	}
	if e = RewriteSrc(b, netip.MustParseAddr("10.66.66.20")); e != nil {
		t.Fatal(e)
	}
	p, _ = Parse(b)
	if p.Src.String() != "10.66.66.20" {
		t.Fatal(p.Src)
	}
}
func TestPaddingTrim(t *testing.T) {
	b := make([]byte, 20)
	b[0] = 0x45
	b[2] = 0
	b[3] = 20
	p := Pad16(b)
	if len(p)%16 != 0 {
		t.Fatal(len(p))
	}
	if len(TrimToIPLength(p)) != 20 {
		t.Fatal()
	}
}

func TestClampTCPMSS(t *testing.T) {
	b := make([]byte, 44)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 44)
	b[8] = 64
	b[9] = 6
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(b[20:22], 1234)
	binary.BigEndian.PutUint16(b[22:24], 443)
	b[32] = 0x60
	b[33] = 0x02
	b[40] = 2
	b[41] = 4
	binary.BigEndian.PutUint16(b[42:44], 1460)
	changed, err := ClampTCPMSS(b, 1340)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := binary.BigEndian.Uint16(b[42:44]); got != 1340 {
		t.Fatalf("mss=%d", got)
	}
}

func TestBuildTCPResetReplyIPv4(t *testing.T) {
	b := make([]byte, 20+20+5)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = ProtoTCP
	copy(b[12:16], []byte{192, 168, 1, 2})
	copy(b[16:20], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(b[20:22], 50000)
	binary.BigEndian.PutUint16(b[22:24], 443)
	binary.BigEndian.PutUint32(b[24:28], 100)
	binary.BigEndian.PutUint32(b[28:32], 900)
	b[32] = 5 << 4
	b[33] = 0x18 // PSH|ACK
	copy(b[40:], []byte("hello"))
	rst, err := BuildTCPResetReply(b)
	if err != nil {
		t.Fatal(err)
	}
	p, ti, err := ParseTCPInfo(rst)
	if err != nil {
		t.Fatal(err)
	}
	if p.Src.String() != "1.2.3.4" || p.Dst.String() != "192.168.1.2" || p.SrcPort != 443 || p.DstPort != 50000 {
		t.Fatalf("wrong reverse tuple: %+v", p)
	}
	if ti.Seq != 900 || ti.Flags != 0x04 {
		t.Fatalf("seq=%d flags=%02x", ti.Seq, ti.Flags)
	}
}

func TestSplitTCPForMTU(t *testing.T) {
	b := make([]byte, 20+20+4000)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = ProtoTCP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[20:22], 12345)
	binary.BigEndian.PutUint16(b[22:24], 443)
	binary.BigEndian.PutUint32(b[24:28], 1000)
	b[32] = 5 << 4
	b[33] = 0x18
	for i := 40; i < len(b); i++ {
		b[i] = byte(i)
	}
	segs, split, err := SplitForMTU(b, 1380)
	if err != nil {
		t.Fatal(err)
	}
	if !split || len(segs) < 2 {
		t.Fatalf("split=%v n=%d", split, len(segs))
	}
	off := 0
	for i, s := range segs {
		if len(s) > 1380 {
			t.Fatalf("segment %d len=%d", i, len(s))
		}
		seq := binary.BigEndian.Uint32(s[24:28])
		if seq != 1000+uint32(off) {
			t.Fatalf("seq=%d off=%d", seq, off)
		}
		off += len(s) - 40
	}
	if off != 4000 {
		t.Fatalf("payload=%d", off)
	}
}

func TestSplitIPv4LSOTemplateOver65535(t *testing.T) {
	b := make([]byte, 65570)
	b[0] = 0x45
	b[8] = 64
	b[9] = ProtoTCP // total length deliberately zero: LSO template
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[20:22], 10000)
	binary.BigEndian.PutUint16(b[22:24], 443)
	b[32] = 5 << 4
	b[33] = 0x10
	segs, split, err := SplitForMTU(b, 1380)
	if err != nil {
		t.Fatal(err)
	}
	if !split || len(segs) < 40 {
		t.Fatalf("split=%v n=%d", split, len(segs))
	}
	for _, s := range segs {
		if len(s) > 1380 || len(s) > 65535 {
			t.Fatalf("bad segment %d", len(s))
		}
	}
}

func TestParseIPv6LSOZeroPayloadLengthUsesCapturedLength(t *testing.T) {
	b := make([]byte, 40+20+2000)
	b[0] = 0x60
	b[6] = ProtoTCP
	b[7] = 64
	b[8] = 0x20
	b[24] = 0x20
	b[40] = 0x30
	b[41] = 0x39
	b[42] = 0x01
	b[43] = 0xbb
	b[52] = 5 << 4
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != len(b) || p.SrcPort != 12345 || p.DstPort != 443 {
		t.Fatalf("p=%+v", p)
	}
}

func TestParseRejectsFirstIPv4FragmentWithMF(t *testing.T) {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:8], 0x2000) // offset 0, more fragments
	b[9] = ProtoUDP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	if _, err := Parse(b); err != ErrFragment {
		t.Fatalf("err=%v want ErrFragment", err)
	}
}

func TestFragmentIPv4ForMTU(t *testing.T) {
	b := make([]byte, 20+8+2400)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], 0x1234)
	b[8] = 64
	b[9] = ProtoUDP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[20:22], 12345)
	binary.BigEndian.PutUint16(b[22:24], 443)
	binary.BigEndian.PutUint16(b[24:26], uint16(len(b)-20))
	frags, split, err := FragmentForMTU(b, 1380)
	if err != nil || !split || len(frags) < 2 {
		t.Fatalf("split=%v n=%d err=%v", split, len(frags), err)
	}
	var payload []byte
	for i, f := range frags {
		if len(f) > 1380 || !IsFragment(f) {
			t.Fatalf("fragment %d len=%d fragmented=%v", i, len(f), IsFragment(f))
		}
		fv := binary.BigEndian.Uint16(f[6:8])
		off := int(fv&0x1fff) * 8
		if off != len(payload) {
			t.Fatalf("fragment %d offset=%d expected=%d", i, off, len(payload))
		}
		payload = append(payload, f[20:]...)
	}
	if len(payload) != len(b)-20 {
		t.Fatalf("payload=%d want=%d", len(payload), len(b)-20)
	}
}

func TestFragmentIPv6ForMTU(t *testing.T) {
	b := make([]byte, 40+8+2200)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	b[6] = ProtoUDP
	b[7] = 64
	b[8] = 0x20
	b[24] = 0x20
	binary.BigEndian.PutUint16(b[40:42], 12345)
	binary.BigEndian.PutUint16(b[42:44], 443)
	binary.BigEndian.PutUint16(b[44:46], uint16(len(b)-40))
	frags, split, err := FragmentForMTU(b, 1380)
	if err != nil || !split || len(frags) < 2 {
		t.Fatalf("split=%v n=%d err=%v", split, len(frags), err)
	}
	for i, f := range frags {
		if len(f) > 1380 || !IsFragment(f) || f[6] != 44 {
			t.Fatalf("fragment %d len=%d isfrag=%v next=%d", i, len(f), IsFragment(f), f[6])
		}
		if f[40] != ProtoUDP {
			t.Fatalf("fragment %d inner next=%d", i, f[40])
		}
	}
}

func TestFragmentIPv6PlacesFragmentBeforeFinalDestinationOptions(t *testing.T) {
	// IPv6 -> final Destination Options -> UDP. The Fragment header belongs
	// before final-destination options, not after them.
	b := make([]byte, 40+8+8+2200)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	b[6] = 60
	b[7] = 64
	b[8] = 0x20
	b[24] = 0x20
	b[40] = ProtoUDP // Destination Options Next Header
	b[41] = 0        // 8-byte extension
	binary.BigEndian.PutUint16(b[48:50], 12345)
	binary.BigEndian.PutUint16(b[50:52], 443)
	binary.BigEndian.PutUint16(b[52:54], uint16(len(b)-48))
	frags, split, err := FragmentForMTU(b, 1380)
	if err != nil || !split || len(frags) < 2 {
		t.Fatalf("split=%v n=%d err=%v", split, len(frags), err)
	}
	if frags[0][6] != 44 {
		t.Fatalf("IPv6 next=%d want Fragment(44)", frags[0][6])
	}
	if frags[0][40] != 60 {
		t.Fatalf("fragment next=%d want DestinationOptions(60)", frags[0][40])
	}
}

func TestFragmentIPv6KeepsPreRoutingDestinationOptionsUnfragmentable(t *testing.T) {
	// IPv6 -> Destination Options (for routing destination) -> Routing -> UDP.
	b := make([]byte, 40+8+8+8+2200)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	b[6] = 60
	b[7] = 64
	b[8] = 0x20
	b[24] = 0x20
	b[40] = 43 // dest opts -> routing
	b[41] = 0
	b[48] = ProtoUDP // routing -> UDP
	b[49] = 0
	binary.BigEndian.PutUint16(b[56:58], 12345)
	binary.BigEndian.PutUint16(b[58:60], 443)
	binary.BigEndian.PutUint16(b[60:62], uint16(len(b)-56))
	frags, split, err := FragmentForMTU(b, 1380)
	if err != nil || !split || len(frags) < 2 {
		t.Fatalf("split=%v n=%d err=%v", split, len(frags), err)
	}
	if frags[0][6] != 60 || frags[0][40] != 43 || frags[0][48] != 44 || frags[0][56] != ProtoUDP {
		t.Fatalf("unexpected chain: ipv6=%d dst=%d routing=%d frag=%d", frags[0][6], frags[0][40], frags[0][48], frags[0][56])
	}
}
