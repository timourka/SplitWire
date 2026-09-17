package reassembly

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	Packet      []byte
	Ready       bool
	Fragmented  bool
	FragmentMTU int // largest original fragment packet length
}

type key struct {
	src, dst [4]byte
	proto    uint8
	id       uint16
}

type piece struct {
	off  int
	data []byte
}

type datagram struct {
	header    []byte
	pieces    []piece
	last      int
	haveLast  bool
	updated   time.Time
	bytes     int
	maxPacket int
}

// IPv4 reassembles IPv4 fragments before classification/NAT. It is deliberately
// bounded because packet input is untrusted.
type IPv4 struct {
	mu         sync.Mutex
	m          map[key]*datagram
	maxEntries int
	maxBytes   int
	bytes      int
	ttl        time.Duration
	expired    atomic.Uint64
}

func NewIPv4() *IPv4 {
	return &IPv4{m: make(map[key]*datagram), maxEntries: 1024, maxBytes: 16 << 20, ttl: 30 * time.Second}
}

// Push keeps the original API for existing callers/tests.
func (r *IPv4) Push(pkt []byte) ([]byte, bool, error) {
	res, err := r.PushInfo(pkt)
	return res.Packet, res.Ready, err
}

// PushInfo returns a complete datagram plus metadata describing whether it had
// to be reassembled and the largest original fragment size (useful for DIRECT
// re-fragmentation after policy classification).
func (r *IPv4) PushInfo(pkt []byte) (Result, error) {
	if len(pkt) < 1 || pkt[0]>>4 != 4 {
		return Result{Packet: pkt, Ready: true}, nil
	}
	if len(pkt) < 20 {
		return Result{}, errors.New("short IPv4 fragment")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return Result{}, errors.New("bad IPv4 IHL")
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total == 0 || total > len(pkt) {
		total = len(pkt)
	}
	if total < ihl {
		return Result{}, errors.New("bad IPv4 fragment length")
	}
	fv := binary.BigEndian.Uint16(pkt[6:8])
	off := int(fv&0x1fff) * 8
	more := fv&0x2000 != 0
	if off == 0 && !more {
		return Result{Packet: pkt[:total], Ready: true}, nil
	}
	pl := append([]byte(nil), pkt[ihl:total]...)
	if len(pl) == 0 {
		return Result{}, errors.New("empty IPv4 fragment")
	}
	if more && len(pl)%8 != 0 {
		return Result{}, errors.New("non-final IPv4 fragment payload is not 8-byte aligned")
	}
	end := off + len(pl)
	if end > 65535-ihl {
		return Result{}, fmt.Errorf("IPv4 reassembly too large: %d", end)
	}
	var k key
	copy(k.src[:], pkt[12:16])
	copy(k.dst[:], pkt[16:20])
	k.proto = pkt[9]
	k.id = binary.BigEndian.Uint16(pkt[4:6])

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	d := r.m[k]
	if d == nil {
		if len(r.m) >= r.maxEntries {
			return Result{}, errors.New("IPv4 reassembly table full")
		}
		d = &datagram{last: -1, updated: now}
		r.m[k] = d
	}
	// Reject overlapping fragments rather than allowing ambiguous reassembly.
	for _, q := range d.pieces {
		if off < q.off+len(q.data) && q.off < end {
			r.dropLocked(k, d)
			return Result{}, errors.New("overlapping IPv4 fragments")
		}
	}
	if r.bytes+len(pl) > r.maxBytes {
		r.dropLocked(k, d)
		return Result{}, errors.New("IPv4 reassembly memory limit")
	}
	d.pieces = append(d.pieces, piece{off: off, data: pl})
	d.bytes += len(pl)
	r.bytes += len(pl)
	d.updated = now
	if total > d.maxPacket {
		d.maxPacket = total
	}
	if off == 0 {
		d.header = append([]byte(nil), pkt[:ihl]...)
	}
	if !more {
		d.last = end
		d.haveLast = true
	}
	if d.header == nil || !d.haveLast {
		return Result{Fragmented: true}, nil
	}
	covered := make([]bool, d.last)
	for _, q := range d.pieces {
		if q.off+len(q.data) > d.last {
			r.dropLocked(k, d)
			return Result{}, errors.New("fragment past final IPv4 length")
		}
		for i := q.off; i < q.off+len(q.data); i++ {
			covered[i] = true
		}
	}
	for _, v := range covered {
		if !v {
			return Result{Fragmented: true}, nil
		}
	}
	if len(d.header)+d.last > 65535 {
		r.dropLocked(k, d)
		return Result{}, errors.New("reassembled IPv4 packet exceeds 65535")
	}
	out := make([]byte, len(d.header)+d.last)
	copy(out, d.header)
	for _, q := range d.pieces {
		copy(out[len(d.header)+q.off:], q.data)
	}
	flags := binary.BigEndian.Uint16(out[6:8]) & 0xC000 // preserve reserved/DF, clear MF+offset
	binary.BigEndian.PutUint16(out[6:8], flags)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[10], out[11] = 0, 0
	mtu := d.maxPacket
	r.dropLocked(k, d)
	return Result{Packet: out, Ready: true, Fragmented: true, FragmentMTU: mtu}, nil
}

func (r *IPv4) dropLocked(k key, d *datagram) {
	if cur := r.m[k]; cur == d {
		delete(r.m, k)
		r.bytes -= d.bytes
		if r.bytes < 0 {
			r.bytes = 0
		}
	}
}

func (r *IPv4) sweepLocked(now time.Time) {
	for k, d := range r.m {
		if now.Sub(d.updated) > r.ttl {
			r.dropLocked(k, d)
			r.expired.Add(1)
		}
	}
}

// TakeExpired returns and clears the number of incomplete datagrams discarded
// by the reassembly TTL since the previous call.
func (r *IPv4) TakeExpired() uint64 { return r.expired.Swap(0) }

func (r *IPv4) Sweep() {
	r.mu.Lock()
	r.sweepLocked(time.Now())
	r.mu.Unlock()
}
