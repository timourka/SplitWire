package tlshello

import (
	"encoding/binary"
	"testing"
)

func clientHello(host string) []byte {
	// Minimal syntactically valid TLS 1.3-ish ClientHello for parser tests.
	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression
	name := []byte(host)
	sni := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sni[:2], uint16(1+2+len(name)))
	sni[2] = 0
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(name)))
	copy(sni[5:], name)
	ext := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(ext[0:2], 0)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sni)))
	copy(ext[4:], sni)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := make([]byte, 4+len(body))
	hs[0] = 1
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	rec := make([]byte, 5+len(hs))
	rec[0], rec[1], rec[2] = 22, 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestServerName(t *testing.T) {
	b := clientHello("ChatGPT.COM")
	n, complete, err := ServerName(b)
	if err != nil || !complete || n != "chatgpt.com" {
		t.Fatalf("got %q complete=%v err=%v", n, complete, err)
	}
}

func TestServerNameFragmented(t *testing.T) {
	b := clientHello("cdn.oaistatic.com")
	if _, complete, err := ServerName(b[:20]); err != nil || complete {
		t.Fatalf("partial: complete=%v err=%v", complete, err)
	}
	n, complete, err := ServerName(b)
	if err != nil || !complete || n != "cdn.oaistatic.com" {
		t.Fatalf("got %q complete=%v err=%v", n, complete, err)
	}
}
