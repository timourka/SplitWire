package browserdisc

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"splitwire/internal/flow"
)

func tlsPacket(seq uint32, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = 6
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(b[20:22], 50000)
	binary.BigEndian.PutUint16(b[22:24], 443)
	binary.BigEndian.PutUint32(b[24:28], seq)
	b[32] = 5 << 4
	b[33] = 0x18
	copy(b[40:], payload)
	return b
}

func hello(host string) []byte {
	name := []byte(host)
	sni := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sni[:2], uint16(3+len(name)))
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(name)))
	copy(sni[5:], name)
	ext := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sni)))
	copy(ext[4:], sni)
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := make([]byte, 4+len(body))
	hs[0] = 1
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	rec := make([]byte, 5+len(hs))
	rec[0] = 22
	rec[1] = 3
	rec[2] = 1
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestFeedTLSAcrossSegments(t *testing.T) {
	d := New()
	h := hello("chatgpt.com")
	k := flow.Key{Proto: 6, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 50000, RemotePort: 443}
	if n, r := d.FeedTLS(k, tlsPacket(100, h[:17])); n != "" || r != TLSNeedMore {
		t.Fatalf("first n=%q r=%v", n, r)
	}
	n, r := d.FeedTLS(k, tlsPacket(117, h[17:]))
	if n != "chatgpt.com" || r != TLSClientHello {
		t.Fatalf("n=%q r=%v", n, r)
	}
}

func TestSuppressUnknownQUICWindow(t *testing.T) {
	d := New()
	now := time.Unix(1000, 0)
	d.now = func() time.Time { return now }
	ip := netip.MustParseAddr("1.2.3.4")
	if !d.SuppressUnknownQUIC(ip) {
		t.Fatal("first should suppress")
	}
	now = now.Add(5 * time.Second)
	if d.SuppressUnknownQUIC(ip) {
		t.Fatal("after block window should not suppress")
	}
	now = now.Add(11 * time.Minute)
	if !d.SuppressUnknownQUIC(ip) {
		t.Fatal("after cooldown should suppress again")
	}
}

func TestClientHelloResultStaysClientHello(t *testing.T) {
	d := New()
	h := hello("example.com")
	k := flow.Key{Proto: 6, Local: netip.MustParseAddr("10.0.0.1"), Remote: netip.MustParseAddr("1.1.1.1"), LocalPort: 50000, RemotePort: 443}
	n, r := d.FeedTLS(k, tlsPacket(100, h))
	if n != "example.com" || r != TLSClientHello {
		t.Fatalf("first n=%q r=%v", n, r)
	}
	n, r = d.FeedTLS(k, tlsPacket(100+uint32(len(h)), []byte{23, 3, 3, 0, 1, 0}))
	if n != "example.com" || r != TLSClientHello {
		t.Fatalf("later n=%q r=%v", n, r)
	}
}
