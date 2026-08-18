package main

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"splitwire/internal/wireguard"
)

func main() {
	var a, b [32]byte
	for i := range a {
		a[i] = 0x10
		b[i] = 0x20
	}
	priv, _ := ecdh.X25519().NewPrivateKey(b[:])
	var pub [32]byte
	copy(pub[:], priv.PublicKey().Bytes())
	c, err := wireguard.New(wireguard.Params{PrivateKey: a, PeerPublicKey: pub, Endpoint: "127.0.0.1:45887"})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 66, 66, 20})
	copy(pkt[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(pkt[20:22], 5555)
	binary.BigEndian.PutUint16(pkt[22:24], 53)
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.SendPacket(ctx, pkt); err != nil {
		panic(err)
	}
	select {
	case got := <-c.Packets():
		if string(got) != string(pkt) {
			panic(fmt.Sprintf("echo mismatch %x", got))
		}
		fmt.Println("GO_WIREGUARD_INTEROP_OK")
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "timeout")
		os.Exit(2)
	}
}
