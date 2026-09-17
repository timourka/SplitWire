package engine

import (
	"context"
	"net"
	"testing"
	"time"
)

// Regression test for 1.1.0's double-bind bug. The helper must both establish
// the TCP connection and leave a route entry registered before the connection
// is accepted by the peer.
func TestDialProxyRegisteredNoDoubleBind(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()

	routes := newProxyRouteTable()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := dialProxyRegistered(ctx, "tcp4", ln.Addr().String(), true, routes, nil)
	if err != nil {
		t.Fatalf("dialProxyRegistered: %v", err)
	}
	defer c.Close()

	select {
	case peer := <-accepted:
		defer peer.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept proxy connection")
	}

	routes.mu.Lock()
	n := len(routes.m)
	routes.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected one pre-registered proxy route, got %d", n)
	}
}

func TestDialProxyRegisteredPreservesPacketConn(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	routes := newProxyRouteTable()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := dialProxyRegistered(ctx, "udp4", server.LocalAddr().String(), true, routes, nil)
	if err != nil {
		t.Fatalf("dialProxyRegistered UDP: %v", err)
	}
	defer c.Close()

	pc, ok := c.(net.PacketConn)
	if !ok {
		t.Fatalf("registered UDP connection lost net.PacketConn: %T", c)
	}

	payload := []byte("dns-datagram")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("UDP write: %v", err)
	}
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, peer, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("UDP server read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload=%q", buf[:n])
	}
	if _, err := server.WriteToUDP([]byte("reply"), peer); err != nil {
		t.Fatalf("UDP server write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = c.Read(buf)
	if err != nil {
		t.Fatalf("UDP client read: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("reply=%q", buf[:n])
	}
}
