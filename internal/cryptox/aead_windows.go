//go:build windows

package cryptox

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var bcrypt = syscall.NewLazyDLL("bcrypt.dll")
var pOpen = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
var pClose = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
var pGetProp = bcrypt.NewProc("BCryptGetProperty")
var pGenKey = bcrypt.NewProc("BCryptGenerateSymmetricKey")
var pDestroyKey = bcrypt.NewProc("BCryptDestroyKey")
var pEncrypt = bcrypt.NewProc("BCryptEncrypt")
var pDecrypt = bcrypt.NewProc("BCryptDecrypt")

type cngAEAD struct {
	alg, key uintptr
	obj      []byte
}
type authInfo struct {
	CbSize        uint32
	Version       uint32
	Nonce         *byte
	NonceLen      uint32
	AuthData      *byte
	AuthDataLen   uint32
	Tag           *byte
	TagLen        uint32
	MacContext    *byte
	MacContextLen uint32
	AADLen        uint32
	DataLen       uint64
	Flags         uint32
}

func ntok(r uintptr) error {
	if int32(r) < 0 {
		return fmt.Errorf("CNG NTSTATUS 0x%08x", uint32(r))
	}
	return nil
}
func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }
func NewChaCha20Poly1305(key [32]byte) (AEAD, error) {
	var alg uintptr
	r, _, _ := pOpen.Call(uintptr(unsafe.Pointer(&alg)), uintptr(unsafe.Pointer(utf16("CHACHA20_POLY1305"))), 0, 0)
	if err := ntok(r); err != nil {
		return nil, fmt.Errorf("BCryptOpenAlgorithmProvider: %w", err)
	}
	var objLen, out uint32
	r, _, _ = pGetProp.Call(alg, uintptr(unsafe.Pointer(utf16("ObjectLength"))), uintptr(unsafe.Pointer(&objLen)), 4, uintptr(unsafe.Pointer(&out)), 0)
	if err := ntok(r); err != nil {
		pClose.Call(alg, 0)
		return nil, fmt.Errorf("BCryptGetProperty(ObjectLength): %w", err)
	}
	obj := make([]byte, objLen)
	var hkey uintptr
	var objPtr uintptr
	if len(obj) > 0 {
		objPtr = uintptr(unsafe.Pointer(&obj[0]))
	}
	r, _, _ = pGenKey.Call(alg, uintptr(unsafe.Pointer(&hkey)), objPtr, uintptr(objLen), uintptr(unsafe.Pointer(&key[0])), 32, 0)
	if err := ntok(r); err != nil {
		pClose.Call(alg, 0)
		return nil, fmt.Errorf("BCryptGenerateSymmetricKey: %w", err)
	}
	return &cngAEAD{alg: alg, key: hkey, obj: obj}, nil
}
func (c *cngAEAD) Close() error {
	if c.key != 0 {
		pDestroyKey.Call(c.key)
		c.key = 0
	}
	if c.alg != 0 {
		pClose.Call(c.alg, 0)
		c.alg = 0
	}
	return nil
}
func ptr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
func (c *cngAEAD) Seal(nonce, pt, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes")
	}
	tag := make([]byte, 16)
	out := make([]byte, len(pt))
	ai := authInfo{CbSize: uint32(unsafe.Sizeof(authInfo{})), Version: 1, Nonce: ptr(nonce), NonceLen: uint32(len(nonce)), AuthData: ptr(aad), AuthDataLen: uint32(len(aad)), Tag: &tag[0], TagLen: 16}
	var n uint32
	var inPtr, outPtr uintptr
	if len(pt) > 0 {
		inPtr = uintptr(unsafe.Pointer(&pt[0]))
		outPtr = uintptr(unsafe.Pointer(&out[0]))
	}
	r, _, _ := pEncrypt.Call(c.key, inPtr, uintptr(len(pt)), uintptr(unsafe.Pointer(&ai)), 0, 0, outPtr, uintptr(len(out)), uintptr(unsafe.Pointer(&n)), 0)
	if err := ntok(r); err != nil {
		return nil, err
	}
	if int(n) != len(out) {
		return nil, fmt.Errorf("CNG encrypt size %d != %d", n, len(out))
	}
	return append(out, tag...), nil
}
func (c *cngAEAD) Open(nonce, ct, aad []byte) ([]byte, error) {
	if len(nonce) != 12 || len(ct) < 16 {
		return nil, ErrAuth
	}
	nct := len(ct) - 16
	tag := append([]byte(nil), ct[nct:]...)
	out := make([]byte, nct)
	ai := authInfo{CbSize: uint32(unsafe.Sizeof(authInfo{})), Version: 1, Nonce: ptr(nonce), NonceLen: uint32(len(nonce)), AuthData: ptr(aad), AuthDataLen: uint32(len(aad)), Tag: &tag[0], TagLen: 16}
	var n uint32
	var inPtr, outPtr uintptr
	if nct > 0 {
		inPtr = uintptr(unsafe.Pointer(&ct[0]))
		outPtr = uintptr(unsafe.Pointer(&out[0]))
	}
	r, _, _ := pDecrypt.Call(c.key, inPtr, uintptr(nct), uintptr(unsafe.Pointer(&ai)), 0, 0, outPtr, uintptr(len(out)), uintptr(unsafe.Pointer(&n)), 0)
	if int32(r) < 0 {
		return nil, ErrAuth
	}
	if int(n) != len(out) {
		return nil, fmt.Errorf("CNG decrypt size %d != %d", n, len(out))
	}
	return out, nil
}
