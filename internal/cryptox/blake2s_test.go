package cryptox

import (
	"encoding/hex"
	"testing"
)

func TestBlake2sEmpty(t *testing.T) {
	got := Blake2s256(nil)
	want, _ := hex.DecodeString("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
	if string(got[:]) != string(want) {
		t.Fatalf("got %x", got)
	}
}
func TestBlake2sABC(t *testing.T) {
	got := Blake2s256([]byte("abc"))
	want, _ := hex.DecodeString("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
	if string(got[:]) != string(want) {
		t.Fatalf("got %x", got)
	}
}
