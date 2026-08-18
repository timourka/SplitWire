package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
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
	if frag&0x1fff != 0 {
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
	total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
	if total > len(b) || total < 40 {
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
