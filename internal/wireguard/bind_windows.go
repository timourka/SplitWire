//go:build windows

package wireguard

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

func bindUDPToInterface(c *net.UDPConn, index uint32, ipv6 bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if ipv6 {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, 31, int(index))
			return
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], index)
		v := *(*uint32)(unsafe.Pointer(&b[0]))
		serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(v))
	})
	if err != nil {
		return err
	}
	return serr
}
