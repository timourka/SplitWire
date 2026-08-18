//go:build !windows

package cryptox

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
)

type pureAEAD struct{ key [32]byte }

func NewChaCha20Poly1305(key [32]byte) (AEAD, error) { return &pureAEAD{key: key}, nil }
func (p *pureAEAD) Close() error                     { return nil }
func (p *pureAEAD) Seal(nonce, pt, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes")
	}
	block := chachaBlock(p.key, 0, nonce)
	var polyKey [32]byte
	copy(polyKey[:], block[:32])
	out := make([]byte, len(pt)+16)
	xorStream(out[:len(pt)], pt, p.key, nonce, 1)
	tag := poly1305Big(polyKey, aad, out[:len(pt)])
	copy(out[len(pt):], tag[:])
	return out, nil
}
func (p *pureAEAD) Open(nonce, ct, aad []byte) ([]byte, error) {
	if len(nonce) != 12 || len(ct) < 16 {
		return nil, ErrAuth
	}
	n := len(ct) - 16
	block := chachaBlock(p.key, 0, nonce)
	var polyKey [32]byte
	copy(polyKey[:], block[:32])
	tag := poly1305Big(polyKey, aad, ct[:n])
	if subtle.ConstantTimeCompare(tag[:], ct[n:]) != 1 {
		return nil, ErrAuth
	}
	out := make([]byte, n)
	xorStream(out, ct[:n], p.key, nonce, 1)
	return out, nil
}
func poly1305Big(key [32]byte, aad, ct []byte) [16]byte {
	msg := make([]byte, 0, len(aad)+len(ct)+64)
	msg = append(msg, aad...)
	for len(msg)%16 != 0 {
		msg = append(msg, 0)
	}
	msg = append(msg, ct...)
	for len(msg)%16 != 0 {
		msg = append(msg, 0)
	}
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ct)))
	msg = append(msg, lens[:]...)
	return poly1305Raw(key, msg)
}
func poly1305Raw(key [32]byte, msg []byte) [16]byte {
	rbytes := append([]byte(nil), key[:16]...)
	rbytes[3] &= 15
	rbytes[7] &= 15
	rbytes[11] &= 15
	rbytes[15] &= 15
	rbytes[4] &= 252
	rbytes[8] &= 252
	rbytes[12] &= 252
	r := leBig(rbytes)
	s := leBig(key[16:])
	mod := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := new(big.Int)
	for len(msg) > 0 {
		n := 16
		if len(msg) < n {
			n = len(msg)
		}
		block := append([]byte(nil), msg[:n]...)
		block = append(block, 1)
		v := leBig(block)
		acc.Add(acc, v)
		acc.Mul(acc, r)
		acc.Mod(acc, mod)
		msg = msg[n:]
	}
	acc.Add(acc, s)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	acc.And(acc, mask)
	be := acc.Bytes()
	var out [16]byte
	for i := range be {
		if i < 16 {
			out[i] = be[len(be)-1-i]
		}
	}
	return out
}
func leBig(b []byte) *big.Int {
	r := append([]byte(nil), b...)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return new(big.Int).SetBytes(r)
}
