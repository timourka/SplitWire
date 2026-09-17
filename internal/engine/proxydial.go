package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type registeredConn struct {
	net.Conn
	routes *proxyRouteTable
	keys   []proxyRouteKey
}

func (c *registeredConn) Close() error {
	if c.routes != nil {
		for _, k := range c.keys {
			c.routes.DeleteKey(k)
		}
	}
	return c.Conn.Close()
}

// registeredPacketConn preserves net.PacketConn when the underlying socket is
// UDP. net.Resolver uses this interface to decide whether DNS messages need
// datagram framing or the two-byte DNS-over-TCP length prefix. Hiding the
// interface makes Go send TCP-framed DNS bytes over UDP and causes timeouts.
type registeredPacketConn struct {
	*registeredConn
	packet net.PacketConn
}

func (c *registeredPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(p)
}

func (c *registeredPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(p, addr)
}

// dialProxyRegistered registers the selected route before connect() emits the
// first packet. resolver, when non-nil, is used to resolve target hostnames.
func dialProxyRegistered(ctx context.Context, network, address string, tunnel bool, routes *proxyRouteTable, resolver *net.Resolver) (net.Conn, error) {
	proto := uint8(6)
	isUDP := strings.HasPrefix(network, "udp")
	if isUDP {
		proto = 17
	} else if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("unsupported proxy network %q", network)
	}
	const attempts = 4
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		localPort, err := reserveSourcePort(network)
		if err != nil {
			return nil, fmt.Errorf("reserve proxy source port: %w", err)
		}
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Resolver: resolver}
		if isUDP {
			d.LocalAddr = &net.UDPAddr{Port: localPort}
		} else {
			d.LocalAddr = &net.TCPAddr{Port: localPort}
		}
		var regMu sync.Mutex
		var registered []proxyRouteKey
		d.ControlContext = func(_ context.Context, _ string, dialAddress string, _ syscall.RawConn) error {
			host, portText, err := net.SplitHostPort(dialAddress)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
			if err != nil {
				return fmt.Errorf("dial address %q not resolved to IP: %w", dialAddress, err)
			}
			port64, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port64 == 0 {
				return fmt.Errorf("bad remote port %q", portText)
			}
			k := proxyRouteKey{Proto: proto, LocalPort: uint16(localPort), Remote: ip.Unmap(), RemotePort: uint16(port64)}
			routes.Set(k, tunnel)
			regMu.Lock()
			registered = append(registered, k)
			regMu.Unlock()
			return nil
		}
		c, err := d.DialContext(ctx, network, address)
		regMu.Lock()
		keys := append([]proxyRouteKey(nil), registered...)
		regMu.Unlock()
		if err == nil {
			rc := &registeredConn{Conn: c, routes: routes, keys: keys}
			if pc, ok := c.(net.PacketConn); ok {
				return &registeredPacketConn{registeredConn: rc, packet: pc}, nil
			}
			return rc, nil
		}
		for _, k := range keys {
			routes.DeleteKey(k)
		}
		lastErr = err
		if !isBindError(err) {
			break
		}
	}
	return nil, lastErr
}

func reserveSourcePort(network string) (int, error) {
	if strings.HasPrefix(network, "udp") {
		c, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
		if err != nil {
			return 0, err
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		err = c.Close()
		return p, err
	}
	ln, err := net.ListenTCP(network, &net.TCPAddr{Port: 0})
	if err != nil {
		return 0, err
	}
	p := ln.Addr().(*net.TCPAddr).Port
	err = ln.Close()
	return p, err
}

func isBindError(err error) bool {
	var se *os.SyscallError
	return errors.As(err, &se) && strings.EqualFold(se.Syscall, "bind")
}

// newTunnelDNSResolver resolves only SplitWire's own tunneled proxy/bootstrap
// hostnames through DNS servers declared in the WireGuard config. It does not
// touch the machine-wide Windows DNS settings.
func newTunnelDNSResolver(servers []netip.Addr, routes *proxyRouteTable) *net.Resolver {
	if len(servers) == 0 {
		return nil
	}
	var n atomic.Uint64
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		i := int((n.Add(1) - 1) % uint64(len(servers)))
		server := servers[i]
		isTCP := strings.HasPrefix(network, "tcp")
		if server.Is4() {
			if isTCP {
				network = "tcp4"
			} else {
				network = "udp4"
			}
		} else {
			if isTCP {
				network = "tcp6"
			} else {
				network = "udp6"
			}
		}
		a := net.JoinHostPort(server.String(), "53")
		return dialProxyRegistered(ctx, network, a, true, routes, nil)
	}}
}

func isDNSLookupError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
