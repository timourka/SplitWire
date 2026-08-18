package cryptox

import "encoding/binary"

func chachaBlock(key [32]byte, counter uint32, nonce []byte) [64]byte {
	var s [16]uint32
	s[0] = 0x61707865
	s[1] = 0x3320646e
	s[2] = 0x79622d32
	s[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:4])
	s[14] = binary.LittleEndian.Uint32(nonce[4:8])
	s[15] = binary.LittleEndian.Uint32(nonce[8:12])
	x := s
	qr := func(a, b, c, d int) {
		x[a] += x[b]
		x[d] = rol(x[d]^x[a], 16)
		x[c] += x[d]
		x[b] = rol(x[b]^x[c], 12)
		x[a] += x[b]
		x[d] = rol(x[d]^x[a], 8)
		x[c] += x[d]
		x[b] = rol(x[b]^x[c], 7)
	}
	for i := 0; i < 10; i++ {
		qr(0, 4, 8, 12)
		qr(1, 5, 9, 13)
		qr(2, 6, 10, 14)
		qr(3, 7, 11, 15)
		qr(0, 5, 10, 15)
		qr(1, 6, 11, 12)
		qr(2, 7, 8, 13)
		qr(3, 4, 9, 14)
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+s[i])
	}
	return out
}
func hChaCha20(key [32]byte, nonce16 []byte) [32]byte {
	var x [16]uint32
	x[0] = 0x61707865
	x[1] = 0x3320646e
	x[2] = 0x79622d32
	x[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		x[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < 4; i++ {
		x[12+i] = binary.LittleEndian.Uint32(nonce16[i*4:])
	}
	qr := func(a, b, c, d int) {
		x[a] += x[b]
		x[d] = rol(x[d]^x[a], 16)
		x[c] += x[d]
		x[b] = rol(x[b]^x[c], 12)
		x[a] += x[b]
		x[d] = rol(x[d]^x[a], 8)
		x[c] += x[d]
		x[b] = rol(x[b]^x[c], 7)
	}
	for i := 0; i < 10; i++ {
		qr(0, 4, 8, 12)
		qr(1, 5, 9, 13)
		qr(2, 6, 10, 14)
		qr(3, 7, 11, 15)
		qr(0, 5, 10, 15)
		qr(1, 6, 11, 12)
		qr(2, 7, 8, 13)
		qr(3, 4, 9, 14)
	}
	var out [32]byte
	vals := []uint32{x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15]}
	for i, v := range vals {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}
func rol(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }
func xorStream(dst, src []byte, key [32]byte, nonce []byte, counter uint32) {
	for len(src) > 0 {
		b := chachaBlock(key, counter, nonce)
		counter++
		n := len(src)
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ b[i]
		}
		dst = dst[n:]
		src = src[n:]
	}
}
