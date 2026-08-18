package cryptox

import "errors"

type AEAD interface {
	Seal(nonce, plaintext, aad []byte) ([]byte, error)
	Open(nonce, ciphertext, aad []byte) ([]byte, error)
	Close() error
}

var ErrAuth = errors.New("authentication failed")

// NewXChaCha wraps ChaCha20-Poly1305 with XChaCha nonce derivation (HChaCha20).
func NewXChaCha(key [32]byte) (AEAD, error) { return &xAEAD{key: key}, nil }

type xAEAD struct{ key [32]byte }

func (x *xAEAD) Close() error { return nil }
func (x *xAEAD) Seal(nonce, pt, aad []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, errors.New("xchacha: nonce must be 24 bytes")
	}
	sub := hChaCha20(x.key, nonce[:16])
	c, err := NewChaCha20Poly1305(sub)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	n := make([]byte, 12)
	copy(n[4:], nonce[16:])
	return c.Seal(n, pt, aad)
}
func (x *xAEAD) Open(nonce, ct, aad []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, errors.New("xchacha: nonce must be 24 bytes")
	}
	sub := hChaCha20(x.key, nonce[:16])
	c, err := NewChaCha20Poly1305(sub)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	n := make([]byte, 12)
	copy(n[4:], nonce[16:])
	return c.Open(n, ct, aad)
}
