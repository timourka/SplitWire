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
	"syscall"
	"time"
)

// dialProxyRegistered preselects an ephemeral source port, registers the route
// from ControlContext, and lets net.Dialer perform the actual bind exactly once.
//
// The ordering matters on Windows. Go's TCP implementation uses ConnectEx and
// ControlContext is called before net binds Dialer.LocalAddr:
//
//	reserve source port -> ControlContext/register -> net bind -> SYN
//
// SplitWire 1.1.0 incorrectly called syscall.Bind from ControlContext and Go
// then attempted its own bind, producing WSAEINVAL ("An invalid argument was
// supplied"). This helper never binds from ControlContext.
func dialProxyRegistered(ctx context.Context, network, address string, tunnel bool, routes *proxyRouteTable) (net.Conn, error) {
	const attempts = 4
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		localPort, err := reserveTCPSourcePort()
		if err != nil {
			return nil, fmt.Errorf("reserve proxy source port: %w", err)
		}

		d := &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: &net.TCPAddr{Port: localPort},
		}
		var registered proxyRouteKey
		d.ControlContext = func(_ context.Context, _ string, dialAddress string, _ syscall.RawConn) error {
			host, portText, err := net.SplitHostPort(dialAddress)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
			if err != nil {
				return fmt.Errorf("proxy dial address %q was not resolved to an IP: %w", dialAddress, err)
			}
			port64, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port64 == 0 {
				return fmt.Errorf("proxy dial invalid remote port %q", portText)
			}
			registered = proxyRouteKey{
				Proto:      6,
				LocalPort:  uint16(localPort),
				Remote:     ip.Unmap(),
				RemotePort: uint16(port64),
			}
			// Registration only. net.Dialer binds LocalAddr immediately after the
			// control hook, before connect/ConnectEx can emit the SYN.
			routes.Set(registered, tunnel)
			return nil
		}

		c, err := d.DialContext(ctx, network, address)
		if err == nil {
			return c, nil
		}
		if registered.LocalPort != 0 {
			routes.DeleteKey(registered)
		}
		lastErr = err
		if !isBindError(err) {
			break
		}
	}
	return nil, lastErr
}

func reserveTCPSourcePort() (int, error) {
	// Ask the OS for an unused ephemeral port. An unconnected listener does not
	// create TIME_WAIT when closed. There is still a tiny race until DialContext
	// binds the port, so bind failures are retried above.
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		return 0, err
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid reserved source port %d", port)
	}
	return port, nil
}

func isBindError(err error) bool {
	var se *os.SyscallError
	return errors.As(err, &se) && strings.EqualFold(se.Syscall, "bind")
}
