package domain

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseDNSResponseA(t *testing.T) {
	// standard response: chatgpt.com A 203.0.113.42 TTL 60
	msg := make([]byte, 0, 64)
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[2:4], 0x8180)
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], 1)
	msg = append(msg, h...)
	msg = append(msg, 7)
	msg = append(msg, []byte("chatgpt")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)
	msg = append(msg, 0, 1, 0, 1)
	msg = append(msg, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 42)
	r, err := ParseDNSResponse(msg, func(s string) bool { return s == "chatgpt.com" })
	if err != nil {
		t.Fatal(err)
	}
	if len(r.IPs) != 1 || r.IPs[0].String() != "203.0.113.42" {
		t.Fatalf("IPs=%v", r.IPs)
	}
	if r.TTL != 60*time.Second {
		t.Fatalf("TTL=%v", r.TTL)
	}
}
