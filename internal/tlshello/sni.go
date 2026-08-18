package tlshello

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrNotClientHello = errors.New("not a TLS ClientHello")
	ErrMalformed      = errors.New("malformed TLS ClientHello")
)

// ServerName parses the SNI server_name from one or more complete TLS records
// starting at the beginning of data. complete is false when more bytes are
// needed. TLS 1.2/1.3 ClientHello use the same clear-text ClientHello structure
// unless Encrypted ClientHello (ECH) hides the real name.
func ServerName(data []byte) (name string, complete bool, err error) {
	if len(data) < 5 {
		return "", false, nil
	}
	// A ClientHello is normally record type handshake (22). Ignore non-TLS data.
	if data[0] != 22 {
		return "", true, ErrNotClientHello
	}
	var hs []byte
	off := 0
	for {
		if len(data)-off < 5 {
			return "", false, nil
		}
		typ := data[off]
		ln := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if ln < 0 || ln > 1<<15 {
			return "", true, ErrMalformed
		}
		if len(data)-off < 5+ln {
			return "", false, nil
		}
		if typ == 22 {
			hs = append(hs, data[off+5:off+5+ln]...)
		}
		off += 5 + ln
		if len(hs) >= 4 {
			hlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if hlen > 1<<20 {
				return "", true, ErrMalformed
			}
			if len(hs) >= 4+hlen {
				return parseClientHello(hs[:4+hlen])
			}
		}
		if off >= len(data) {
			return "", false, nil
		}
	}
}

func parseClientHello(hs []byte) (string, bool, error) {
	if len(hs) < 4 || hs[0] != 1 { // handshake_type client_hello
		return "", true, ErrNotClientHello
	}
	hlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hlen {
		return "", false, nil
	}
	b := hs[4 : 4+hlen]
	// legacy_version(2) + random(32)
	if len(b) < 34 {
		return "", true, ErrMalformed
	}
	off := 34
	if off >= len(b) {
		return "", true, ErrMalformed
	}
	sidLen := int(b[off])
	off++
	if off+sidLen+2 > len(b) {
		return "", true, ErrMalformed
	}
	off += sidLen
	csLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if csLen == 0 || csLen%2 != 0 || off+csLen+1 > len(b) {
		return "", true, ErrMalformed
	}
	off += csLen
	compLen := int(b[off])
	off++
	if off+compLen > len(b) {
		return "", true, ErrMalformed
	}
	off += compLen
	if off == len(b) {
		return "", true, nil
	}
	if off+2 > len(b) {
		return "", true, ErrMalformed
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extLen > len(b) {
		return "", true, ErrMalformed
	}
	end := off + extLen
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(b[off : off+2])
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+ln > end {
			return "", true, ErrMalformed
		}
		if typ == 0 { // server_name
			x := b[off : off+ln]
			if len(x) < 2 {
				return "", true, ErrMalformed
			}
			listLen := int(binary.BigEndian.Uint16(x[:2]))
			if 2+listLen > len(x) {
				return "", true, ErrMalformed
			}
			p := 2
			for p+3 <= 2+listLen {
				nameType := x[p]
				n := int(binary.BigEndian.Uint16(x[p+1 : p+3]))
				p += 3
				if p+n > 2+listLen {
					return "", true, ErrMalformed
				}
				if nameType == 0 && n > 0 {
					name := strings.ToLower(strings.TrimSuffix(string(x[p:p+n]), "."))
					return name, true, nil
				}
				p += n
			}
			return "", true, nil
		}
		off += ln
	}
	return "", true, nil
}
