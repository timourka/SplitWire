package browserproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPAC(t *testing.T) {
	s, err := Start(context.Background(), []string{"chatgpt.com", "*.chatgpt.com", "*.googlevideo.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pac := s.PAC()
	if !strings.Contains(pac, "chatgpt.com") || !strings.Contains(pac, ".googlevideo.com") || !strings.Contains(pac, s.Addr()) {
		t.Fatalf("bad PAC: %s", pac)
	}
	got, err := ProbePAC(s.PACURL())
	if err != nil {
		t.Fatal(err)
	}
	if got != pac {
		t.Fatalf("served PAC differs")
	}
}

func TestHostMatchStrictWildcards(t *testing.T) {
	s := &Server{patterns: normalize([]string{"chatgpt.com", "*.chatgpt.com", "*.oaistatic.com"})}
	for _, h := range []string{"chatgpt.com", "www.chatgpt.com", "cdn.oaistatic.com"} {
		if !s.matchesHost(h) {
			t.Fatalf("expected match %s", h)
		}
	}
	for _, h := range []string{"example.com", "chatgpt.com.evil.test", "oaistatic.com"} {
		if s.matchesHost(h) {
			t.Fatalf("unexpected match %s", h)
		}
	}
}

func TestProxyPassesPerClientRouteToDial(t *testing.T) {
	for _, wantTunnel := range []bool{false, true} {
		t.Run(fmt.Sprintf("tunnel_%v", wantTunnel), func(t *testing.T) {
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				c, e := target.Accept()
				if e == nil {
					defer c.Close()
					_, _ = bufio.NewReader(c).ReadByte()
				}
			}()

			var routeSeen atomic.Bool
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := Start(ctx, []string{"localhost"}, func(client, proxy, host string) (bool, string) {
				if client == "" || proxy == "" || host != "localhost" {
					t.Errorf("bad authorize args client=%q proxy=%q host=%q", client, proxy, host)
				}
				return wantTunnel, "test"
			}, func(ctx context.Context, network, address string, tunnel bool) (net.Conn, error) {
				if tunnel == wantTunnel {
					routeSeen.Store(true)
				}
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			c, err := net.DialTimeout("tcp", s.Addr(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			fmt.Fprintf(c, "CONNECT localhost:%d HTTP/1.1\r\nHost: localhost:%d\r\n\r\n", target.Addr().(*net.TCPAddr).Port, target.Addr().(*net.TCPAddr).Port)
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(line, "200") {
				t.Fatalf("CONNECT failed: %s", line)
			}
			if !routeSeen.Load() {
				t.Fatalf("dial did not receive tunnel=%v", wantTunnel)
			}
		})
	}
}
