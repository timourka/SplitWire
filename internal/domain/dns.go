package domain

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

type DNSResult struct {
	Names []string
	IPs   []netip.Addr
	TTL   time.Duration
}

func ParseDNSResponse(msg []byte, match func(string) bool) (DNSResult, error) {
	if len(msg) < 12 {
		return DNSResult{}, errors.New("short dns")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return DNSResult{}, errors.New("not response")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	matched := false
	res := DNSResult{TTL: 5 * time.Minute}
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off, 0)
		if err != nil {
			return res, err
		}
		off = n
		if off+4 > len(msg) {
			return res, errors.New("short question")
		}
		off += 4
		res.Names = append(res.Names, name)
		if match(name) {
			matched = true
		}
	}
	type answer struct {
		name     string
		typ      uint16
		ttl      uint32
		rdataOff int
		rdlen    int
	}
	answers := make([]answer, 0, an)
	for i := 0; i < an; i++ {
		name, n, err := readName(msg, off, 0)
		if err != nil {
			return res, err
		}
		off = n
		if off+10 > len(msg) {
			return res, errors.New("short answer")
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		ttl := binary.BigEndian.Uint32(msg[off+4:])
		rd := int(binary.BigEndian.Uint16(msg[off+8:]))
		ro := off + 10
		if ro+rd > len(msg) {
			return res, errors.New("short rdata")
		}
		answers = append(answers, answer{name, typ, ttl, ro, rd})
		off = ro + rd
		if match(name) {
			matched = true
		}
		if typ == 5 {
			cn, _, e := readName(msg, ro, 0)
			if e == nil {
				res.Names = append(res.Names, cn)
				if match(cn) {
					matched = true
				}
			}
		}
	}
	if !matched {
		return res, nil
	}
	minTTL := uint32(86400)
	for _, a := range answers {
		switch a.typ {
		case 1:
			if a.rdlen == 4 {
				var v [4]byte
				copy(v[:], msg[a.rdataOff:a.rdataOff+4])
				res.IPs = append(res.IPs, netip.AddrFrom4(v))
				if a.ttl < minTTL {
					minTTL = a.ttl
				}
			}
		case 28:
			if a.rdlen == 16 {
				var v [16]byte
				copy(v[:], msg[a.rdataOff:a.rdataOff+16])
				res.IPs = append(res.IPs, netip.AddrFrom16(v))
				if a.ttl < minTTL {
					minTTL = a.ttl
				}
			}
		}
	}
	if minTTL != 86400 {
		res.TTL = time.Duration(minTTL) * time.Second
	}
	return res, nil
}
func readName(msg []byte, off, depth int) (string, int, error) {
	if depth > 16 {
		return "", off, errors.New("dns compression loop")
	}
	var out []byte
	next := off
	jumped := false
	for {
		if off >= len(msg) {
			return "", next, errors.New("name overflow")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			if !jumped {
				next = off
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", next, errors.New("bad pointer")
			}
			ptr := ((l & 0x3f) << 8) | int(msg[off+1])
			suffix, _, err := readName(msg, ptr, depth+1)
			if err != nil {
				return "", next, err
			}
			if len(out) > 0 && suffix != "" {
				out = append(out, '.')
			}
			out = append(out, []byte(suffix)...)
			if !jumped {
				next = off + 2
			}
			jumped = true
			break
		}
		off++
		if l > 63 || off+l > len(msg) {
			return "", next, errors.New("bad label")
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		out = append(out, msg[off:off+l]...)
		off += l
		if !jumped {
			next = off
		}
	}
	return string(out), next, nil
}
