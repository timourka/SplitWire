package browserdisc

import (
	"net/netip"
	"sync"
	"time"

	"splitwire/internal/flow"
	"splitwire/internal/packet"
	"splitwire/internal/tlshello"
)

type tlsState struct {
	buf     []byte
	nextSeq uint32
	setSeq  bool
	expires time.Time
	done    bool
	result  TLSResult
	name    string
}

type quicState struct {
	blockUntil time.Time
	coolUntil  time.Time
}

type TLSResult uint8

const (
	TLSNeedMore TLSResult = iota
	TLSClientHello
	TLSNotClientHello
)

type Discovery struct {
	mu    sync.Mutex
	tls   map[flow.Key]*tlsState
	reset map[flow.Key]bool
	quic  map[netip.Addr]quicState
	now   func() time.Time
}

func New() *Discovery {
	return &Discovery{tls: map[flow.Key]*tlsState{}, reset: map[flow.Key]bool{}, quic: map[netip.Addr]quicState{}, now: time.Now}
}

// FeedTLS appends TCP payload in sequence order and returns a parsed SNI once a
// ClientHello is complete. TLSNotClientHello is useful for connections that
// were already established before SplitWire started: resetting them once makes
// Chrome reconnect so the new ClientHello can be classified.
func (d *Discovery) FeedTLS(k flow.Key, raw []byte) (name string, result TLSResult) {
	_, ti, err := packet.ParseTCPInfo(raw)
	if err != nil || len(ti.Payload) == 0 {
		return "", TLSNeedMore
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	s := d.tls[k]
	if s == nil || now.After(s.expires) {
		s = &tlsState{expires: now.Add(30 * time.Second)}
		d.tls[k] = s
	}
	if s.done {
		return s.name, s.result
	}
	seq := ti.Seq
	payload := ti.Payload
	if !s.setSeq {
		s.nextSeq = seq
		s.setSeq = true
	}
	if seq < s.nextSeq {
		over := int(s.nextSeq - seq)
		if over >= len(payload) {
			return "", TLSNeedMore
		}
		payload = payload[over:]
		seq = s.nextSeq
	}
	if seq != s.nextSeq {
		s.buf = nil
		s.nextSeq = seq
	}
	if len(s.buf)+len(payload) > 64*1024 {
		s.done = true
		s.result = TLSNotClientHello
		return "", s.result
	}
	s.buf = append(s.buf, payload...)
	s.nextSeq += uint32(len(payload))
	name, complete, parseErr := tlshello.ServerName(s.buf)
	if !complete {
		return "", TLSNeedMore
	}
	s.done = true
	if parseErr != nil {
		s.result = TLSNotClientHello
		return "", s.result
	}
	s.result = TLSClientHello
	s.name = name
	return s.name, s.result
}

func (d *Discovery) DeleteFlow(k flow.Key) {
	d.mu.Lock()
	delete(d.tls, k)
	delete(d.reset, k)
	d.mu.Unlock()
}

// MarkReset returns true only the first time it is called for a flow.
func (d *Discovery) MarkReset(k flow.Key) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reset[k] {
		return false
	}
	d.reset[k] = true
	return true
}

// SuppressUnknownQUIC returns true during a short first-contact window for an
// unknown browser destination. This nudges Chrome to TCP, where SNI can be
// observed even when Chrome's Secure DNS/DoH hides DNS packets from WinDivert.
// After the window expires there is a cooldown so unrelated websites are not
// permanently forced off HTTP/3.
func (d *Discovery) SuppressUnknownQUIC(ip netip.Addr) bool {
	ip = ip.Unmap()
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	s, ok := d.quic[ip]
	if !ok || now.After(s.coolUntil) {
		d.quic[ip] = quicState{blockUntil: now.Add(4 * time.Second), coolUntil: now.Add(10 * time.Minute)}
		return true
	}
	return now.Before(s.blockUntil)
}

func (d *Discovery) Sweep() {
	d.mu.Lock()
	now := d.now()
	for k, s := range d.tls {
		if now.After(s.expires) {
			delete(d.tls, k)
		}
	}
	for ip, s := range d.quic {
		if now.After(s.coolUntil) {
			delete(d.quic, ip)
		}
	}
	d.mu.Unlock()
}
