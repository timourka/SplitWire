package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestSessionUsableRekeysWithoutRejectingCurrentTraffic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &session{created: now.Add(-109 * time.Second)}
	if usable, rekey := sessionUsable(s, now); !usable || rekey {
		t.Fatalf("109s: usable=%v rekey=%v, want true/false", usable, rekey)
	}

	s.created = now.Add(-110 * time.Second)
	if usable, rekey := sessionUsable(s, now); !usable || !rekey {
		t.Fatalf("110s: usable=%v rekey=%v, want true/true", usable, rekey)
	}

	s.created = now.Add(-169 * time.Second)
	if usable, rekey := sessionUsable(s, now); !usable || !rekey {
		t.Fatalf("169s: usable=%v rekey=%v, want true/true", usable, rekey)
	}

	s.created = now.Add(-170 * time.Second)
	if usable, rekey := sessionUsable(s, now); usable || rekey {
		t.Fatalf("170s: usable=%v rekey=%v, want false/false", usable, rekey)
	}
}

func TestSessionUsableRejectsCounterLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &session{created: now}
	s.sendCounter.Store(1 << 60)
	if usable, rekey := sessionUsable(s, now); usable || rekey {
		t.Fatalf("counter limit: usable=%v rekey=%v, want false/false", usable, rekey)
	}
}

func TestHandshakeSwitchesPathAfterThirdTimeout(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	curve := ecdh.X25519()
	clientKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var privateKey, peerPublicKey [32]byte
	copy(privateKey[:], clientKey.Bytes())
	copy(peerPublicKey[:], peerKey.PublicKey().Bytes())

	c, err := New(Params{
		PrivateKey:    privateKey,
		PeerPublicKey: peerPublicKey,
		Endpoint:      server.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	oldTimeout := handshakeAttemptTimeout
	handshakeAttemptTimeout = 25 * time.Millisecond
	defer func() { handshakeAttemptTimeout = oldTimeout }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.handshake(ctx, "test"); err == nil {
		t.Fatal("handshake unexpectedly succeeded against silent peer")
	}

	if err := server.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	var ports []int
	for len(ports) < 5 {
		_, from, err := server.ReadFromUDP(buf)
		if err != nil {
			break
		}
		ports = append(ports, from.Port)
	}
	if len(ports) != 5 {
		t.Fatalf("got %d handshake datagrams, want 5; ports=%v", len(ports), ports)
	}
	if ports[0] != ports[1] || ports[1] != ports[2] {
		t.Fatalf("attempts 1..3 must stay on the original path: %v", ports)
	}
	if ports[3] == ports[0] {
		t.Fatalf("attempt 4 must switch path after the third timeout: %v", ports)
	}
	if ports[4] != ports[3] {
		t.Fatalf("attempts 4..5 must stay on the new path: %v", ports)
	}
	if got := c.LocalPort(); got != ports[3] {
		t.Fatalf("active port=%d, want switched port=%d", got, ports[3])
	}
	if got := c.StandbyPort(); got != ports[0] {
		t.Fatalf("standby port=%d, want old active port=%d", got, ports[0])
	}
}
