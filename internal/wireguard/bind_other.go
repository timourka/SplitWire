//go:build !windows

package wireguard

import "net"

func bindUDPToInterface(c *net.UDPConn, index uint32, ipv6 bool) error { return nil }
