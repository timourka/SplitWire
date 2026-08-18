package cryptox

import (
	"encoding/binary"
	"errors"
)

var blakeIV = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
var sigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func Blake2s256(data []byte) [32]byte {
	x, _ := Blake2s(data, nil, 32)
	var out [32]byte
	copy(out[:], x)
	return out
}
func Blake2s128Keyed(key, data []byte) [16]byte {
	x, _ := Blake2s(data, key, 16)
	var out [16]byte
	copy(out[:], x)
	return out
}

func Blake2s(data, key []byte, outLen int) ([]byte, error) {
	if outLen < 1 || outLen > 32 {
		return nil, errors.New("blake2s: invalid output size")
	}
	if len(key) > 32 {
		return nil, errors.New("blake2s: key too long")
	}
	h := blakeIV
	h[0] ^= 0x01010000 ^ uint32(len(key))<<8 ^ uint32(outLen)
	msg := make([]byte, 0, len(data)+64)
	if len(key) > 0 {
		kb := make([]byte, 64)
		copy(kb, key)
		msg = append(msg, kb...)
	}
	msg = append(msg, data...)
	if len(msg) == 0 {
		var block [64]byte
		compress(&h, block[:], 0, true)
	} else {
		total := uint64(0)
		for len(msg) > 64 {
			total += 64
			compress(&h, msg[:64], total, false)
			msg = msg[64:]
		}
		total += uint64(len(msg))
		var block [64]byte
		copy(block[:], msg)
		compress(&h, block[:], total, true)
	}
	full := make([]byte, 32)
	for i, v := range h {
		binary.LittleEndian.PutUint32(full[i*4:], v)
	}
	return full[:outLen], nil
}
func compress(h *[8]uint32, block []byte, t uint64, last bool) {
	var m [16]uint32
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	var v [16]uint32
	copy(v[:8], h[:])
	copy(v[8:], blakeIV[:])
	v[12] ^= uint32(t)
	v[13] ^= uint32(t >> 32)
	if last {
		v[14] = ^v[14]
	}
	for r := 0; r < 10; r++ {
		s := sigma[r]
		g := func(a, b, c, d int, x, y uint32) {
			v[a] = v[a] + v[b] + x
			v[d] = ror(v[d]^v[a], 16)
			v[c] += v[d]
			v[b] = ror(v[b]^v[c], 12)
			v[a] = v[a] + v[b] + y
			v[d] = ror(v[d]^v[a], 8)
			v[c] += v[d]
			v[b] = ror(v[b]^v[c], 7)
		}
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}
func ror(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }

// WireGuard's KDF is HKDF-like HMAC-BLAKE2s.
func HMACBlake2s(key []byte, parts ...[]byte) [32]byte {
	const block = 64
	if len(key) > block {
		s := Blake2s256(key)
		key = s[:]
	}
	var ipad, opad [block]byte
	for i := 0; i < block; i++ {
		ipad[i] = 0x36
		opad[i] = 0x5c
	}
	for i, b := range key {
		ipad[i] ^= b
		opad[i] ^= b
	}
	inner := make([]byte, 0, block+128)
	inner = append(inner, ipad[:]...)
	for _, p := range parts {
		inner = append(inner, p...)
	}
	ih := Blake2s256(inner)
	outer := append(opad[:0:0], opad[:]...)
	outer = append(outer, ih[:]...)
	return Blake2s256(outer)
}
func KDF1(key, input []byte) (t0 [32]byte) {
	prk := HMACBlake2s(key, input)
	return HMACBlake2s(prk[:], []byte{1})
}
func KDF2(key, input []byte) (t0, t1 [32]byte) {
	prk := HMACBlake2s(key, input)
	t0 = HMACBlake2s(prk[:], []byte{1})
	t1 = HMACBlake2s(prk[:], t0[:], []byte{2})
	return
}
func KDF3(key, input []byte) (t0, t1, t2 [32]byte) {
	prk := HMACBlake2s(key, input)
	t0 = HMACBlake2s(prk[:], []byte{1})
	t1 = HMACBlake2s(prk[:], t0[:], []byte{2})
	t2 = HMACBlake2s(prk[:], t1[:], []byte{3})
	return
}
