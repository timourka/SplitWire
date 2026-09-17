package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
)

const (
	ProtoTCP = 6
	ProtoUDP = 17
)

var ErrFragment = errors.New("fragmented packet not supported")

type Packet struct {
	Version          int
	Protocol         uint8
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	L4               int
	Total            int
}

func Parse(b []byte) (Packet, error) {
	if len(b) < 1 {
		return Packet{}, errors.New("short packet")
	}
	switch b[0] >> 4 {
	case 4:
		return parse4(b)
	case 6:
		return parse6(b)
	default:
		return Packet{}, errors.New("not IP")
	}
}
func parse4(b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, errors.New("short ipv4")
	}
	ihl := int(b[0]&15) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, errors.New("bad ipv4 ihl")
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x3fff != 0 { // MF or non-zero fragment offset
		return Packet{}, ErrFragment
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		total = len(b)
	}
	p := Packet{Version: 4, Protocol: b[9], Src: netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), Dst: netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]}), L4: ihl, Total: total}
	ports(b, &p)
	return p, nil
}
func parse6(b []byte) (Packet, error) {
	if len(b) < 40 {
		return Packet{}, errors.New("short ipv6")
	}
	var s, d [16]byte
	copy(s[:], b[8:24])
	copy(d[:], b[24:40])
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	total := 40 + plen
	if (plen == 0 && len(b) > 40) || total > len(b) || total < 40 {
		total = len(b)
	}
	next := b[6]
	off := 40
	for {
		switch next {
		case 0, 43, 60:
			if off+2 > total {
				return Packet{}, errors.New("short ipv6 extension")
			}
			next = b[off]
			n := (int(b[off+1]) + 1) * 8
			if off+n > total {
				return Packet{}, errors.New("bad ipv6 extension")
			}
			off += n
		case 44:
			return Packet{}, ErrFragment
		case 51:
			if off+2 > total {
				return Packet{}, errors.New("short ah")
			}
			next = b[off]
			n := (int(b[off+1]) + 2) * 4
			if off+n > total {
				return Packet{}, errors.New("bad ah")
			}
			off += n
		default:
			p := Packet{Version: 6, Protocol: next, Src: netip.AddrFrom16(s), Dst: netip.AddrFrom16(d), L4: off, Total: total}
			ports(b, &p)
			return p, nil
		}
	}
}
func ports(b []byte, p *Packet) {
	if (p.Protocol == ProtoTCP || p.Protocol == ProtoUDP) && p.L4+4 <= p.Total {
		p.SrcPort = binary.BigEndian.Uint16(b[p.L4:])
		p.DstPort = binary.BigEndian.Uint16(b[p.L4+2:])
	}
}
func RewriteSrc(b []byte, a netip.Addr) error {
	p, e := Parse(b)
	if e != nil {
		return e
	}
	if p.Version == 4 && a.Is4() {
		v := a.As4()
		copy(b[12:16], v[:])
		return nil
	}
	if p.Version == 6 && a.Is6() {
		v := a.As16()
		copy(b[8:24], v[:])
		return nil
	}
	return fmt.Errorf("source address family mismatch")
}
func RewriteSrcPort(b []byte, port uint16) error {
	p, e := Parse(b)
	if e != nil {
		return e
	}
	if p.Protocol != ProtoTCP && p.Protocol != ProtoUDP {
		return fmt.Errorf("not tcp/udp")
	}
	if p.L4+2 > len(b) {
		return errors.New("short l4")
	}
	binary.BigEndian.PutUint16(b[p.L4:p.L4+2], port)
	return nil
}
func RewriteDstPort(b []byte, port uint16) error {
	p, e := Parse(b)
	if e != nil {
		return e
	}
	if p.Protocol != ProtoTCP && p.Protocol != ProtoUDP {
		return fmt.Errorf("not tcp/udp")
	}
	if p.L4+4 > len(b) {
		return errors.New("short l4")
	}
	binary.BigEndian.PutUint16(b[p.L4+2:p.L4+4], port)
	return nil
}
func RewriteDst(b []byte, a netip.Addr) error {
	p, e := Parse(b)
	if e != nil {
		return e
	}
	if p.Version == 4 && a.Is4() {
		v := a.As4()
		copy(b[16:20], v[:])
		return nil
	}
	if p.Version == 6 && a.Is6() {
		v := a.As16()
		copy(b[24:40], v[:])
		return nil
	}
	return fmt.Errorf("destination address family mismatch")
}
func TrimToIPLength(b []byte) []byte {
	if len(b) < 1 {
		return b
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) >= 4 {
			n := int(binary.BigEndian.Uint16(b[2:4]))
			if n >= 20 && n <= len(b) {
				return b[:n]
			}
		}
	case 6:
		if len(b) >= 6 {
			n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
			if n >= 40 && n <= len(b) {
				return b[:n]
			}
		}
	}
	return b
}
func Pad16(b []byte) []byte {
	n := (16 - len(b)%16) % 16
	if n == 0 {
		return append([]byte(nil), b...)
	}
	out := make([]byte, len(b)+n)
	copy(out, b)
	return out
}

// ClampTCPMSS lowers the MSS option on TCP SYN/SYN-ACK packets. It returns
// true when the packet was changed. This prevents Windows large-MSS flows from
// producing inner packets that exceed the encrypted tunnel's target MTU.
func ClampTCPMSS(b []byte, maxMSS uint16) (bool, error) {
	p, err := Parse(b)
	if err != nil {
		return false, err
	}
	if p.Protocol != ProtoTCP || p.L4+20 > p.Total {
		return false, nil
	}
	// SYN bit. No need to touch established packets.
	if b[p.L4+13]&0x02 == 0 {
		return false, nil
	}
	hlen := int(b[p.L4+12]>>4) * 4
	if hlen < 20 || p.L4+hlen > p.Total {
		return false, errors.New("bad tcp header length")
	}
	for off := p.L4 + 20; off < p.L4+hlen; {
		kind := b[off]
		if kind == 0 {
			break
		}
		if kind == 1 {
			off++
			continue
		}
		if off+2 > p.L4+hlen {
			return false, errors.New("short tcp option")
		}
		ln := int(b[off+1])
		if ln < 2 || off+ln > p.L4+hlen {
			return false, errors.New("bad tcp option length")
		}
		if kind == 2 && ln == 4 {
			cur := binary.BigEndian.Uint16(b[off+2 : off+4])
			if cur > maxMSS {
				binary.BigEndian.PutUint16(b[off+2:off+4], maxMSS)
				return true, nil
			}
			return false, nil
		}
		off += ln
	}
	return false, nil
}

// TCPInfo returns header metadata for a parsed TCP packet.
type TCPInfo struct {
	HeaderLen int
	Seq       uint32
	Ack       uint32
	Flags     uint8
	Payload   []byte
}

func ParseTCPInfo(b []byte) (Packet, TCPInfo, error) {
	p, err := Parse(b)
	if err != nil {
		return Packet{}, TCPInfo{}, err
	}
	if p.Protocol != ProtoTCP || p.L4+20 > p.Total {
		return Packet{}, TCPInfo{}, errors.New("not a complete TCP packet")
	}
	hlen := int(b[p.L4+12]>>4) * 4
	if hlen < 20 || p.L4+hlen > p.Total {
		return Packet{}, TCPInfo{}, errors.New("bad tcp header length")
	}
	return p, TCPInfo{
		HeaderLen: hlen,
		Seq:       binary.BigEndian.Uint32(b[p.L4+4 : p.L4+8]),
		Ack:       binary.BigEndian.Uint32(b[p.L4+8 : p.L4+12]),
		Flags:     b[p.L4+13],
		Payload:   b[p.L4+hlen : p.Total],
	}, nil
}

// BuildTCPResetReply creates an inbound reset that closes the local TCP socket
// corresponding to outbound. Checksums are intentionally left zero; callers
// should run WinDivertHelperCalcChecksums before injection.
func BuildTCPResetReply(outbound []byte) ([]byte, error) {
	p, ti, err := ParseTCPInfo(outbound)
	if err != nil {
		return nil, err
	}
	segLen := uint32(len(ti.Payload))
	if ti.Flags&0x02 != 0 { // SYN
		segLen++
	}
	if ti.Flags&0x01 != 0 { // FIN
		segLen++
	}
	var seq, ack uint32
	flags := uint8(0x04)    // RST
	if ti.Flags&0x10 != 0 { // ACK set: reset sequence is SEG.ACK
		seq = ti.Ack
	} else {
		ack = ti.Seq + segLen
		flags |= 0x10
	}

	if p.Version == 4 {
		b := make([]byte, 40)
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[8] = 64
		b[9] = ProtoTCP
		s := p.Dst.As4()
		d := p.Src.As4()
		copy(b[12:16], s[:])
		copy(b[16:20], d[:])
		binary.BigEndian.PutUint16(b[20:22], p.DstPort)
		binary.BigEndian.PutUint16(b[22:24], p.SrcPort)
		binary.BigEndian.PutUint32(b[24:28], seq)
		binary.BigEndian.PutUint32(b[28:32], ack)
		b[32] = 5 << 4
		b[33] = flags
		binary.BigEndian.PutUint16(b[34:36], 0)
		return b, nil
	}
	if p.Version == 6 {
		b := make([]byte, 60)
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:6], 20)
		b[6] = ProtoTCP
		b[7] = 64
		s := p.Dst.As16()
		d := p.Src.As16()
		copy(b[8:24], s[:])
		copy(b[24:40], d[:])
		binary.BigEndian.PutUint16(b[40:42], p.DstPort)
		binary.BigEndian.PutUint16(b[42:44], p.SrcPort)
		binary.BigEndian.PutUint32(b[44:48], seq)
		binary.BigEndian.PutUint32(b[48:52], ack)
		b[52] = 5 << 4
		b[53] = flags
		return b, nil
	}
	return nil, errors.New("unsupported IP version")
}

// IsTCPSYN reports whether b is a TCP SYN (with or without ACK).
func IsTCPSYN(b []byte) bool {
	p, err := Parse(b)
	return err == nil && p.Protocol == ProtoTCP && p.L4+14 <= p.Total && b[p.L4+13]&0x02 != 0
}

// SplitForMTU turns a Windows outbound TCP LSO packet into ordinary IP/TCP
// packets no larger than mtu. Ordinary packets are returned unchanged. UDP is
// intentionally not byte-sliced here: IP fragmentation has different semantics
// and oversize UDP is rejected by the WireGuard layer instead of being silently
// emitted as an oversize outer datagram.
func SplitForMTU(b []byte, mtu int) ([][]byte, bool, error) {
	if mtu < 576 {
		return nil, false, fmt.Errorf("bad MTU %d", mtu)
	}
	if len(b) <= mtu {
		return [][]byte{append([]byte(nil), b...)}, false, nil
	}
	p, err := Parse(b)
	if err != nil {
		return nil, false, err
	}
	if p.Protocol != ProtoTCP {
		return nil, false, fmt.Errorf("oversize non-TCP inner packet: %d > MTU %d", len(b), mtu)
	}
	// WinDivert NETWORK can expose an outbound LSO super-packet before the NIC
	// performs hardware segmentation. In that case the IP payload-length field
	// may describe only a normal segment (or be zero for IPv6) while Recv() has
	// returned the whole super-packet. The WinDivert packet length is authoritative
	// for the captured LSO template.
	p.Total = len(b)
	if p.L4+20 > len(b) {
		return nil, false, errors.New("short TCP LSO packet")
	}
	tcpHL := int(b[p.L4+12]>>4) * 4
	if tcpHL < 20 || p.L4+tcpHL > len(b) {
		return nil, false, errors.New("bad TCP header in LSO packet")
	}
	maxPayload := mtu - p.L4 - tcpHL
	if maxPayload <= 0 {
		return nil, false, fmt.Errorf("MTU %d too small for headers %d", mtu, p.L4+tcpHL)
	}
	payload := b[p.L4+tcpHL:]
	if len(payload) == 0 {
		return nil, false, fmt.Errorf("oversize TCP packet without payload: %d", len(b))
	}
	baseSeq := binary.BigEndian.Uint32(b[p.L4+4 : p.L4+8])
	origFlags := b[p.L4+13]
	// SYN consumes sequence space and is not an LSO data template in normal use.
	if origFlags&0x02 != 0 {
		return nil, false, errors.New("oversize TCP SYN cannot be segmented")
	}
	out := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for off := 0; off < len(payload); off += maxPayload {
		end := off + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		seg := make([]byte, p.L4+tcpHL+(end-off))
		copy(seg, b[:p.L4+tcpHL])
		copy(seg[p.L4+tcpHL:], payload[off:end])
		binary.BigEndian.PutUint32(seg[p.L4+4:p.L4+8], baseSeq+uint32(off))
		flags := origFlags
		if end != len(payload) {
			flags &^= 0x01 | 0x08 | 0x80
		} // FIN, PSH, CWR only on last
		seg[p.L4+13] = flags
		// Checksums are recalculated after NAT/segmentation by the engine.
		seg[p.L4+16], seg[p.L4+17] = 0, 0
		if p.Version == 4 {
			if len(seg) > 65535 {
				return nil, false, errors.New("segmented IPv4 packet still too large")
			}
			binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
			seg[10], seg[11] = 0, 0
		} else {
			plen := len(seg) - 40
			if plen > 65535 {
				return nil, false, errors.New("segmented IPv6 payload still too large")
			}
			binary.BigEndian.PutUint16(seg[4:6], uint16(plen))
		}
		out = append(out, seg)
	}
	return out, true, nil
}

// IsFragment reports whether b carries an IPv4 fragment (MF or non-zero
// offset) or an IPv6 Fragment extension header.
func IsFragment(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 8 {
			return false
		}
		return binary.BigEndian.Uint16(b[6:8])&0x3fff != 0
	case 6:
		_, _, _, found, _ := ipv6FragmentPoint(b)
		return found
	default:
		return false
	}
}

var fragmentID uint32

// FragmentForMTU fragments a complete IP datagram to mtu. It is intended for
// UDP/non-LSO traffic after transport checksums/NAT are finalized. TCP LSO must
// use SplitForMTU instead so TCP sequence numbers are corrected per segment.
func FragmentForMTU(b []byte, mtu int) ([][]byte, bool, error) {
	if mtu < 576 {
		return nil, false, fmt.Errorf("bad MTU %d", mtu)
	}
	if len(b) <= mtu {
		return [][]byte{append([]byte(nil), b...)}, false, nil
	}
	if len(b) < 1 {
		return nil, false, errors.New("empty IP packet")
	}
	switch b[0] >> 4 {
	case 4:
		return fragmentIPv4(b, mtu)
	case 6:
		return fragmentIPv6(b, mtu)
	default:
		return nil, false, errors.New("not IP")
	}
}

func fragmentIPv4(b []byte, mtu int) ([][]byte, bool, error) {
	if len(b) < 20 {
		return nil, false, errors.New("short ipv4")
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return nil, false, errors.New("bad ipv4 ihl")
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total == 0 || total > len(b) {
		total = len(b)
	}
	if total <= mtu {
		return [][]byte{append([]byte(nil), b[:total]...)}, false, nil
	}
	fv := binary.BigEndian.Uint16(b[6:8])
	if fv&0x3fff != 0 {
		return nil, false, errors.New("IPv4 packet is already fragmented")
	}
	if fv&0x4000 != 0 {
		return nil, false, fmt.Errorf("IPv4 DF packet %d exceeds MTU %d", total, mtu)
	}
	maxPayload := ((mtu - ihl) / 8) * 8
	if maxPayload < 8 {
		return nil, false, fmt.Errorf("MTU %d too small for IPv4 header %d", mtu, ihl)
	}
	payload := b[ihl:total]
	id := binary.BigEndian.Uint16(b[4:6])
	if id == 0 {
		id = uint16(atomic.AddUint32(&fragmentID, 1))
		if id == 0 {
			id = uint16(atomic.AddUint32(&fragmentID, 1))
		}
	}
	reserved := fv & 0x8000
	out := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for off := 0; off < len(payload); {
		n := len(payload) - off
		more := n > maxPayload
		if more {
			n = maxPayload
		}
		frag := make([]byte, ihl+n)
		copy(frag, b[:ihl])
		copy(frag[ihl:], payload[off:off+n])
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))
		binary.BigEndian.PutUint16(frag[4:6], id)
		flagsOff := reserved | uint16(off/8)
		if more {
			flagsOff |= 0x2000
		}
		binary.BigEndian.PutUint16(frag[6:8], flagsOff)
		frag[10], frag[11] = 0, 0
		binary.BigEndian.PutUint16(frag[10:12], ipv4HeaderChecksum(frag[:ihl]))
		out = append(out, frag)
		off += n
	}
	return out, true, nil
}

func ipv4HeaderChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	if len(h)%2 != 0 {
		sum += uint32(h[len(h)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipv6FragmentPoint walks the unfragmentable extension chain. insert is the
// byte offset where a Fragment header is/should be placed, prevNext is the byte
// containing the Next Header value that points at insert, and next is the upper
// header currently referenced there. found is true when a Fragment header is
// already present.
func ipv6FragmentPoint(b []byte) (insert, prevNext int, next uint8, found bool, err error) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return 0, 0, 0, false, errors.New("short/non-IPv6 packet")
	}
	total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
	if total < 40 || total > len(b) {
		total = len(b)
	}
	next = b[6]
	prevNext = 6
	off := 40
	for {
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if off+2 > total {
				return 0, 0, 0, false, errors.New("short ipv6 extension")
			}
			n := (int(b[off+1]) + 1) * 8
			if n < 8 || off+n > total {
				return 0, 0, 0, false, errors.New("bad ipv6 extension")
			}
			prevNext = off
			next = b[off]
			off += n
		case 51: // AH
			if off+2 > total {
				return 0, 0, 0, false, errors.New("short ah")
			}
			n := (int(b[off+1]) + 2) * 4
			if n < 8 || off+n > total {
				return 0, 0, 0, false, errors.New("bad ah")
			}
			prevNext = off
			next = b[off]
			off += n
		case 44:
			if off+8 > total {
				// Preserve found=true so callers can fail closed instead of
				// treating a malformed fragment as ordinary DIRECT traffic.
				return off, prevNext, next, true, errors.New("short ipv6 fragment header")
			}
			return off, prevNext, next, true, nil
		default:
			return off, prevNext, next, false, nil
		}
	}
}

// ipv6FragmentInsertPoint returns the standards-compliant position for a new
// Fragment header. Per RFC 8200, Hop-by-Hop and the routing portion are
// unfragmentable; AH and final-destination options belong after Fragment.
func ipv6FragmentInsertPoint(b []byte) (insert, prevNext int, next uint8, err error) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return 0, 0, 0, errors.New("short/non-IPv6 packet")
	}
	total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
	if total < 40 || total > len(b) {
		return 0, 0, 0, errors.New("truncated IPv6 packet")
	}
	next = b[6]
	prevNext = 6
	off := 40
	for {
		switch next {
		case 0, 43: // Hop-by-Hop, Routing: part of the unfragmentable chain.
			if off+2 > total {
				return 0, 0, 0, errors.New("short IPv6 extension")
			}
			n := (int(b[off+1]) + 1) * 8
			if n < 8 || off+n > total {
				return 0, 0, 0, errors.New("bad IPv6 extension")
			}
			prevNext = off
			next = b[off]
			off += n
		case 60: // Destination Options is unfragmentable only before Routing.
			if off+2 > total {
				return 0, 0, 0, errors.New("short IPv6 destination options")
			}
			n := (int(b[off+1]) + 1) * 8
			if n < 8 || off+n > total {
				return 0, 0, 0, errors.New("bad IPv6 destination options")
			}
			if b[off] != 43 {
				return off, prevNext, next, nil
			}
			prevNext = off
			next = b[off]
			off += n
		case 44:
			return 0, 0, 0, errors.New("IPv6 packet is already fragmented")
		default:
			// AH/ESP/final Destination Options/upper-layer data are fragmentable.
			return off, prevNext, next, nil
		}
	}
}

func fragmentIPv6(b []byte, mtu int) ([][]byte, bool, error) {
	if len(b) < 40 {
		return nil, false, errors.New("short ipv6")
	}
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	if plen == 0 {
		return nil, false, errors.New("IPv6 jumbogram fragmentation is unsupported")
	}
	total := 40 + plen
	if total > len(b) {
		return nil, false, errors.New("truncated ipv6 packet")
	}
	if total <= mtu {
		return [][]byte{append([]byte(nil), b[:total]...)}, false, nil
	}
	_, _, _, found, err := ipv6FragmentPoint(b[:total])
	if err != nil {
		return nil, false, err
	}
	if found {
		return nil, false, errors.New("IPv6 packet is already fragmented")
	}
	insert, prevNext, next, err := ipv6FragmentInsertPoint(b[:total])
	if err != nil {
		return nil, false, err
	}
	maxPayload := ((mtu - insert - 8) / 8) * 8
	if maxPayload < 8 {
		return nil, false, fmt.Errorf("MTU %d too small for IPv6 headers %d", mtu, insert+8)
	}
	payload := b[insert:total]
	id := atomic.AddUint32(&fragmentID, 1)
	if id == 0 {
		id = atomic.AddUint32(&fragmentID, 1)
	}
	out := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for off := 0; off < len(payload); {
		n := len(payload) - off
		more := n > maxPayload
		if more {
			n = maxPayload
		}
		frag := make([]byte, insert+8+n)
		copy(frag, b[:insert])
		frag[prevNext] = 44
		frag[insert] = next
		// frag[insert+1] is reserved zero.
		v := uint16((off / 8) << 3)
		if more {
			v |= 1
		}
		binary.BigEndian.PutUint16(frag[insert+2:insert+4], v)
		binary.BigEndian.PutUint32(frag[insert+4:insert+8], id)
		copy(frag[insert+8:], payload[off:off+n])
		if len(frag)-40 > 65535 {
			return nil, false, errors.New("fragmented IPv6 payload exceeds 65535")
		}
		binary.BigEndian.PutUint16(frag[4:6], uint16(len(frag)-40))
		out = append(out, frag)
		off += n
	}
	return out, true, nil
}
