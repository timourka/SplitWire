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
	c, err := dialProxyRegistered(ctx, "tcp4", ln.Addr().String(), true, routes)
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
