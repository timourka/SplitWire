package reassembly

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type key6 struct {
	src, dst [16]byte
	id       uint32
	next     uint8
}

type datagram6 struct {
	prefix    []byte
	prevNext  int
	next      uint8
	pieces    []piece
	last      int
	haveLast  bool
	updated   time.Time
	bytes     int
	maxPacket int
}

// IPv6 reassembles packets carrying the IPv6 Fragment extension header before
// classification/NAT. It is bounded independently from IPv4 reassembly.
type IPv6 struct {
	mu         sync.Mutex
	m          map[key6]*datagram6
	maxEntries int
	maxBytes   int
	bytes      int
	ttl        time.Duration
	expired    atomic.Uint64
}

func NewIPv6() *IPv6 {
	return &IPv6{m: make(map[key6]*datagram6), maxEntries: 1024, maxBytes: 16 << 20, ttl: 30 * time.Second}
}

func (r *IPv6) Push(pkt []byte) ([]byte, bool, error) {
	res, err := r.PushInfo(pkt)
	return res.Packet, res.Ready, err
}

func (r *IPv6) PushInfo(pkt []byte) (Result, error) {
	if len(pkt) < 1 || pkt[0]>>4 != 6 {
		return Result{Packet: pkt, Ready: true}, nil
	}
	if len(pkt) < 40 {
		return Result{}, errors.New("short IPv6 fragment")
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen == 0 {
		return Result{}, errors.New("IPv6 jumbogram reassembly is unsupported")
	}
	total := 40 + plen
	if total > len(pkt) {
		return Result{}, errors.New("truncated IPv6 packet")
	}
	fragOff, prevNext, found, err := findIPv6Fragment(pkt[:total])
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{Packet: pkt[:total], Ready: true}, nil
	}
	if fragOff+8 > total {
		return Result{}, errors.New("short IPv6 fragment header")
	}
	next := pkt[fragOff]
	fv := binary.BigEndian.Uint16(pkt[fragOff+2 : fragOff+4])
	off := int(fv>>3) * 8
	more := fv&1 != 0
	pld := append([]byte(nil), pkt[fragOff+8:total]...)
	if len(pld) == 0 && more {
		return Result{}, errors.New("empty non-final IPv6 fragment")
	}
	if more && len(pld)%8 != 0 {
		return Result{}, errors.New("non-final IPv6 fragment payload is not 8-byte aligned")
	}
	end := off + len(pld)
	if end > 65535 {
		return Result{}, fmt.Errorf("IPv6 reassembly fragmentable part too large: %d", end)
	}
	var k key6
	copy(k.src[:], pkt[8:24])
	copy(k.dst[:], pkt[24:40])
	k.id = binary.BigEndian.Uint32(pkt[fragOff+4 : fragOff+8])
	k.next = next

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	d := r.m[k]
	if d == nil {
		if len(r.m) >= r.maxEntries {
			return Result{}, errors.New("IPv6 reassembly table full")
		}
		d = &datagram6{last: -1, updated: now, next: next, prevNext: prevNext}
		d.prefix = append([]byte(nil), pkt[:fragOff]...)
		r.m[k] = d
	} else if d.prevNext != prevNext || len(d.prefix) != fragOff {
		r.dropLocked(k, d)
		return Result{}, errors.New("inconsistent IPv6 fragment header chain")
	}
	for _, q := range d.pieces {
		if off < q.off+len(q.data) && q.off < end {
			r.dropLocked(k, d)
			return Result{}, errors.New("overlapping IPv6 fragments")
		}
	}
	if r.bytes+len(pld) > r.maxBytes {
		r.dropLocked(k, d)
		return Result{}, errors.New("IPv6 reassembly memory limit")
	}
	d.pieces = append(d.pieces, piece{off: off, data: pld})
	d.bytes += len(pld)
	r.bytes += len(pld)
	d.updated = now
	if total > d.maxPacket {
		d.maxPacket = total
	}
	if !more {
		d.last = end
		d.haveLast = true
	}
	if !d.haveLast {
		return Result{Fragmented: true}, nil
	}
	covered := make([]bool, d.last)
	for _, q := range d.pieces {
		if q.off+len(q.data) > d.last {
			r.dropLocked(k, d)
			return Result{}, errors.New("fragment past final IPv6 length")
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
	if len(d.prefix)+d.last-40 > 65535 {
		r.dropLocked(k, d)
		return Result{}, errors.New("reassembled IPv6 payload exceeds 65535")
	}
	out := make([]byte, len(d.prefix)+d.last)
	copy(out, d.prefix)
	if d.prevNext < 0 || d.prevNext >= len(out) {
		r.dropLocked(k, d)
		return Result{}, errors.New("invalid IPv6 previous next-header offset")
	}
	out[d.prevNext] = d.next
	for _, q := range d.pieces {
		copy(out[len(d.prefix)+q.off:], q.data)
	}
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	mtu := d.maxPacket
	r.dropLocked(k, d)
	return Result{Packet: out, Ready: true, Fragmented: true, FragmentMTU: mtu}, nil
}

// findIPv6Fragment returns the Fragment header offset and the byte offset of
// the Next Header field that points to it.
func findIPv6Fragment(pkt []byte) (fragOff, prevNext int, found bool, err error) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return 0, 0, false, errors.New("short/non-IPv6 packet")
	}
	total := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
	if total > len(pkt) || total < 40 {
		total = len(pkt)
	}
	next := pkt[6]
	prevNext = 6
	off := 40
	for {
		switch next {
		case 0, 43, 60:
			if off+2 > total {
				return 0, 0, false, errors.New("short IPv6 extension")
			}
			n := (int(pkt[off+1]) + 1) * 8
			if n < 8 || off+n > total {
				return 0, 0, false, errors.New("bad IPv6 extension")
			}
			prevNext = off
			next = pkt[off]
			off += n
		case 51:
			if off+2 > total {
				return 0, 0, false, errors.New("short IPv6 AH")
			}
			n := (int(pkt[off+1]) + 2) * 4
			if n < 8 || off+n > total {
				return 0, 0, false, errors.New("bad IPv6 AH")
			}
			prevNext = off
			next = pkt[off]
			off += n
		case 44:
			return off, prevNext, true, nil
		default:
			return 0, 0, false, nil
		}
	}
}

func (r *IPv6) dropLocked(k key6, d *datagram6) {
	if cur := r.m[k]; cur == d {
		delete(r.m, k)
		r.bytes -= d.bytes
		if r.bytes < 0 {
			r.bytes = 0
		}
	}
}

func (r *IPv6) sweepLocked(now time.Time) {
	for k, d := range r.m {
		if now.Sub(d.updated) > r.ttl {
			r.dropLocked(k, d)
			r.expired.Add(1)
		}
	}
}

// TakeExpired returns and clears the number of incomplete datagrams discarded
// by the reassembly TTL since the previous call.
func (r *IPv6) TakeExpired() uint64 { return r.expired.Swap(0) }

func (r *IPv6) Sweep() {
	r.mu.Lock()
	r.sweepLocked(time.Now())
	r.mu.Unlock()
}
