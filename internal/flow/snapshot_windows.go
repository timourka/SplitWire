//go:build windows

package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

// Existing Windows TCP/UDP endpoints are sampled through IP Helper rather than
// netstat. WinDivert FLOW events are not retroactive, so without this snapshot
// an application that already had an established connection when SplitWire was
// started could be temporarily unclassified.

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1

	mibTCPStateEstablished = 5

	errorInsufficientBuffer syscall.Errno = 122
)

var (
	modIPHlpAPI             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modIPHlpAPI.NewProc("GetExtendedUdpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// SnapshotExisting adds ownership information for endpoints that existed
// before the WinDivert FLOW handle was opened. resolve is called at most once
// for each PID during this snapshot. It returns the number of TCP connections
// and UDP endpoints imported.
func (i *Index) SnapshotExisting(resolve func(uint32) Process) (tcpCount, udpCount int, err error) {
	if resolve == nil {
		resolve = func(pid uint32) Process { return Process{PID: pid} }
	}
	cache := make(map[uint32]Process)
	owner := func(pid uint32) Process {
		if p, ok := cache[pid]; ok {
			return p
		}
		p := NormalizeProcess(resolve(pid))
		if p.PID == 0 {
			p.PID = pid
		}
		cache[pid] = p
		return p
	}

	var errs []error
	if n, e := i.snapshotTCP4(owner); e != nil {
		errs = append(errs, fmt.Errorf("TCP/IPv4: %w", e))
	} else {
		tcpCount += n
	}
	if n, e := i.snapshotTCP6(owner); e != nil {
		errs = append(errs, fmt.Errorf("TCP/IPv6: %w", e))
	} else {
		tcpCount += n
	}
	if n, e := i.snapshotUDP4(owner); e != nil {
		errs = append(errs, fmt.Errorf("UDP/IPv4: %w", e))
	} else {
		udpCount += n
	}
	if n, e := i.snapshotUDP6(owner); e != nil {
		errs = append(errs, fmt.Errorf("UDP/IPv6: %w", e))
	} else {
		udpCount += n
	}
	return tcpCount, udpCount, errors.Join(errs...)
}

func getExtendedTable(proc *syscall.LazyProc, family, class uint32) ([]byte, error) {
	var size uint32
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
	if r != 0 && syscall.Errno(r) != errorInsufficientBuffer {
		return nil, syscall.Errno(r)
	}
	if size < 4 {
		return nil, fmt.Errorf("invalid table size %d", size)
	}
	buf := make([]byte, size)
	r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	if size > uint32(len(buf)) {
		return nil, fmt.Errorf("table grew to %d bytes", size)
	}
	return buf[:size], nil
}

func rows[T any](buf []byte) ([]T, error) {
	if len(buf) < 4 {
		return nil, errors.New("short table")
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	var zero T
	sz := int(unsafe.Sizeof(zero))
	if sz <= 0 {
		return nil, errors.New("invalid row size")
	}
	need := 4 + int(n)*sz
	if need > len(buf) {
		return nil, fmt.Errorf("truncated table: need %d, have %d", need, len(buf))
	}
	out := make([]T, n)
	for j := range out {
		off := 4 + j*sz
		out[j] = *(*T)(unsafe.Pointer(&buf[off]))
	}
	return out, nil
}

func addr4(v uint32) netip.Addr {
	// MIB tables keep IPv4 addresses in network byte order. Reading the four
	// in-memory bytes is independent of the host integer endianness.
	b := *(*[4]byte)(unsafe.Pointer(&v))
	return netip.AddrFrom4(b).Unmap()
}

func mibPort(v uint32) uint16 {
	b := *(*[4]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(b[:2])
}

func wildcardAddr(a netip.Addr) netip.Addr {
	if !a.IsValid() || a.IsUnspecified() {
		return netip.Addr{}
	}
	return a.Unmap()
}

func (i *Index) snapshotTCP4(owner func(uint32) Process) (int, error) {
	buf, err := getExtendedTable(procGetExtendedTCPTable, afInet, tcpTableOwnerPIDAll)
	if err != nil {
		return 0, err
	}
	rs, err := rows[mibTCPRowOwnerPID](buf)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.State != mibTCPStateEstablished || r.OwningPID == 0 {
			continue
		}
		local, remote := addr4(r.LocalAddr), addr4(r.RemoteAddr)
		lp, rp := mibPort(r.LocalPort), mibPort(r.RemotePort)
		if lp == 0 || rp == 0 || remote.IsUnspecified() {
			continue
		}
		i.Add(Key{Proto: 6, Local: local, Remote: remote, LocalPort: lp, RemotePort: rp}, owner(r.OwningPID))
		n++
	}
	return n, nil
}

func (i *Index) snapshotTCP6(owner func(uint32) Process) (int, error) {
	buf, err := getExtendedTable(procGetExtendedTCPTable, afInet6, tcpTableOwnerPIDAll)
	if err != nil {
		return 0, err
	}
	rs, err := rows[mibTCP6RowOwnerPID](buf)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.State != mibTCPStateEstablished || r.OwningPID == 0 {
			continue
		}
		local := netip.AddrFrom16(r.LocalAddr).Unmap()
		remote := netip.AddrFrom16(r.RemoteAddr).Unmap()
		lp, rp := mibPort(r.LocalPort), mibPort(r.RemotePort)
		if lp == 0 || rp == 0 || remote.IsUnspecified() {
			continue
		}
		i.Add(Key{Proto: 6, Local: local, Remote: remote, LocalPort: lp, RemotePort: rp}, owner(r.OwningPID))
		n++
	}
	return n, nil
}

func (i *Index) snapshotUDP4(owner func(uint32) Process) (int, error) {
	buf, err := getExtendedTable(procGetExtendedUDPTable, afInet, udpTableOwnerPID)
	if err != nil {
		return 0, err
	}
	rs, err := rows[mibUDPRowOwnerPID](buf)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.OwningPID == 0 {
			continue
		}
		lp := mibPort(r.LocalPort)
		if lp == 0 {
			continue
		}
		i.AddLocal(17, wildcardAddr(addr4(r.LocalAddr)), lp, owner(r.OwningPID))
		n++
	}
	return n, nil
}

func (i *Index) snapshotUDP6(owner func(uint32) Process) (int, error) {
	buf, err := getExtendedTable(procGetExtendedUDPTable, afInet6, udpTableOwnerPID)
	if err != nil {
		return 0, err
	}
	rs, err := rows[mibUDP6RowOwnerPID](buf)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.OwningPID == 0 {
			continue
		}
		lp := mibPort(r.LocalPort)
		if lp == 0 {
			continue
		}
		local := wildcardAddr(netip.AddrFrom16(r.LocalAddr).Unmap())
		i.AddLocal(17, local, lp, owner(r.OwningPID))
		n++
	}
	return n, nil
}

// ResolveSocketOwner performs an on-demand IP Helper lookup for the exact
// outbound socket. It is used for the first SYN/datagram: WinDivert FLOW events
// may arrive only after the network packet that caused the flow, while routing
// that first packet is essential for moving the whole connection into WG.
func (i *Index) ResolveSocketOwner(k Key, resolve func(uint32) Process) (Process, bool) {
	if resolve == nil {
		resolve = func(pid uint32) Process { return Process{PID: pid} }
	}
	var pid uint32
	var ok bool
	if k.Proto == 6 {
		if k.Local.Is4() && k.Remote.Is4() {
			pid, ok = resolveTCP4Owner(k)
		} else if k.Local.Is6() && k.Remote.Is6() {
			pid, ok = resolveTCP6Owner(k)
		}
	} else if k.Proto == 17 {
		if k.Local.Is4() {
			pid, ok = resolveUDP4Owner(k)
		} else if k.Local.Is6() {
			pid, ok = resolveUDP6Owner(k)
		}
	}
	if !ok || pid == 0 {
		return Process{}, false
	}
	p := NormalizeProcess(resolve(pid))
	if p.PID == 0 {
		p.PID = pid
	}
	i.Add(k, p)
	return p, true
}

func resolveTCP4Owner(k Key) (uint32, bool) {
	buf, err := getExtendedTable(procGetExtendedTCPTable, afInet, tcpTableOwnerPIDAll)
	if err != nil {
		return 0, false
	}
	rs, err := rows[mibTCPRowOwnerPID](buf)
	if err != nil {
		return 0, false
	}
	for _, r := range rs {
		if r.OwningPID == 0 {
			continue
		}
		if mibPort(r.LocalPort) != k.LocalPort || mibPort(r.RemotePort) != k.RemotePort {
			continue
		}
		la, ra := addr4(r.LocalAddr), addr4(r.RemoteAddr)
		if !ra.IsUnspecified() && ra != k.Remote.Unmap() {
			continue
		}
		if !la.IsUnspecified() && la != k.Local.Unmap() {
			continue
		}
		return r.OwningPID, true
	}
	return 0, false
}
func resolveTCP6Owner(k Key) (uint32, bool) {
	buf, err := getExtendedTable(procGetExtendedTCPTable, afInet6, tcpTableOwnerPIDAll)
	if err != nil {
		return 0, false
	}
	rs, err := rows[mibTCP6RowOwnerPID](buf)
	if err != nil {
		return 0, false
	}
	for _, r := range rs {
		if r.OwningPID == 0 {
			continue
		}
		if mibPort(r.LocalPort) != k.LocalPort || mibPort(r.RemotePort) != k.RemotePort {
			continue
		}
		la, ra := netip.AddrFrom16(r.LocalAddr).Unmap(), netip.AddrFrom16(r.RemoteAddr).Unmap()
		if !ra.IsUnspecified() && ra != k.Remote.Unmap() {
			continue
		}
		if !la.IsUnspecified() && la != k.Local.Unmap() {
			continue
		}
		return r.OwningPID, true
	}
	return 0, false
}
func resolveUDP4Owner(k Key) (uint32, bool) {
	buf, err := getExtendedTable(procGetExtendedUDPTable, afInet, udpTableOwnerPID)
	if err != nil {
		return 0, false
	}
	rs, err := rows[mibUDPRowOwnerPID](buf)
	if err != nil {
		return 0, false
	}
	for _, r := range rs {
		if r.OwningPID == 0 || mibPort(r.LocalPort) != k.LocalPort {
			continue
		}
		la := addr4(r.LocalAddr)
		if !la.IsUnspecified() && la != k.Local.Unmap() {
			continue
		}
		return r.OwningPID, true
	}
	return 0, false
}
func resolveUDP6Owner(k Key) (uint32, bool) {
	buf, err := getExtendedTable(procGetExtendedUDPTable, afInet6, udpTableOwnerPID)
	if err != nil {
		return 0, false
	}
	rs, err := rows[mibUDP6RowOwnerPID](buf)
	if err != nil {
		return 0, false
	}
	for _, r := range rs {
		if r.OwningPID == 0 || mibPort(r.LocalPort) != k.LocalPort {
			continue
		}
		la := netip.AddrFrom16(r.LocalAddr).Unmap()
		if !la.IsUnspecified() && la != k.Local.Unmap() {
			continue
		}
		return r.OwningPID, true
	}
	return 0, false
}
