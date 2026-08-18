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
