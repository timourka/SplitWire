//go:build windows

package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"splitwire/internal/flow"
)

const (
	LayerNetwork = 0
	LayerFlow    = 2

	EventNetworkPacket   = 0
	EventFlowEstablished = 1
	EventFlowDeleted     = 2

	FlagSniff    = 0x0001
	FlagDrop     = 0x0002
	FlagRecvOnly = 0x0004
	FlagSendOnly = 0x0008

	priorityDefault = 0
)

var (
	modWinDivert      = syscall.NewLazyDLL("WinDivert.dll")
	procOpen          = modWinDivert.NewProc("WinDivertOpen")
	procRecv          = modWinDivert.NewProc("WinDivertRecv")
	procSend          = modWinDivert.NewProc("WinDivertSend")
	procClose         = modWinDivert.NewProc("WinDivertClose")
	procCalcChecksums = modWinDivert.NewProc("WinDivertHelperCalcChecksums")
	procFormatIPv6    = modWinDivert.NewProc("WinDivertHelperFormatIPv6Address")

	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = modKernel32.NewProc("OpenProcess")
	procCloseHandle                = modKernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

const invalidHandle = ^uintptr(0)

// Address is the WinDivert 2.x WINDIVERT_ADDRESS structure. The public header
// guarantees an 80 byte address structure for the ABI used by WinDivert 2.x.
type Address struct{ Raw [80]byte }

type NetworkMeta struct{ IfIdx, SubIfIdx uint32 }

type Handle struct {
	h     uintptr
	layer uint8
}

type FlowEvent struct {
	Event   uint8
	Key     flow.Key
	Process flow.Process
}

func OpenNetwork(filter string, priority int16, flags uint64) (*Handle, error) {
	return open(filter, LayerNetwork, priority, flags)
}

func OpenFlow(filter string, priority int16) (*Handle, error) {
	return open(filter, LayerFlow, priority, FlagSniff|FlagRecvOnly)
}

func open(filter string, layer uint8, priority int16, flags uint64) (*Handle, error) {
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(f)),
		uintptr(layer),
		uintptr(uint16(priority)),
		uintptr(flags),
	)
	if r == 0 || r == invalidHandle {
		if callErr == syscall.Errno(0) {
			callErr = errors.New("unknown WinDivertOpen error")
		}
		return nil, fmt.Errorf("WinDivertOpen layer=%d filter=%q: %w", layer, filter, callErr)
	}
	return &Handle{h: r, layer: layer}, nil
}

func (h *Handle) Close() error {
	if h == nil || h.h == 0 || h.h == invalidHandle {
		return nil
	}
	r, _, e := procClose.Call(h.h)
	h.h = 0
	if r == 0 && e != syscall.Errno(0) {
		return e
	}
	return nil
}

func (h *Handle) Recv(buf []byte) ([]byte, Address, error) {
	var addr Address
	var n uint32
	var ptr uintptr
	var capn uintptr
	if len(buf) > 0 {
		ptr = uintptr(unsafe.Pointer(&buf[0]))
		capn = uintptr(len(buf))
	}
	r, _, e := procRecv.Call(h.h, ptr, capn, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&addr.Raw[0])))
	if r == 0 {
		if e == syscall.Errno(0) {
			e = errors.New("WinDivertRecv failed")
		}
		return nil, addr, e
	}
	if int(n) > len(buf) {
		return nil, addr, fmt.Errorf("WinDivertRecv length %d exceeds buffer", n)
	}
	return buf[:n], addr, nil
}

func (h *Handle) Send(pkt []byte, addr Address) error {
	if len(pkt) == 0 {
		return nil
	}
	var n uint32
	r, _, e := procSend.Call(h.h, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&addr.Raw[0])))
	if r == 0 {
		if e == syscall.Errno(0) {
			e = errors.New("WinDivertSend failed")
		}
		return e
	}
	if int(n) != len(pkt) {
		return fmt.Errorf("WinDivertSend short write %d/%d", n, len(pkt))
	}
	return nil
}

func CalcChecksums(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	r, _, e := procCalcChecksums.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), 0, 0)
	if r == 0 && e != syscall.Errno(0) {
		return e
	}
	return nil
}

func (a Address) NetworkMeta() NetworkMeta {
	return NetworkMeta{IfIdx: binary.LittleEndian.Uint32(a.Raw[16:20]), SubIfIdx: binary.LittleEndian.Uint32(a.Raw[20:24])}
}

// NewInboundAddress creates metadata for injecting a decrypted packet as if it
// arrived from the interface on which the original flow was sent.
func NewInboundAddress(meta NetworkMeta, ipv6 bool) Address {
	var a Address
	// layer/event are zero (NETWORK / NETWORK_PACKET). Outbound stays false.
	var bits uint64
	if ipv6 {
		bits |= 1 << 20
	}
	binary.LittleEndian.PutUint64(a.Raw[8:16], bits)
	binary.LittleEndian.PutUint32(a.Raw[16:20], meta.IfIdx)
	binary.LittleEndian.PutUint32(a.Raw[20:24], meta.SubIfIdx)
	return a
}

func addressEvent(a *Address) uint8 {
	return uint8((binary.LittleEndian.Uint64(a.Raw[8:16]) >> 8) & 0xff)
}

func (h *Handle) RecvFlow() (FlowEvent, error) {
	if h.layer != LayerFlow {
		return FlowEvent{}, errors.New("RecvFlow called on non-FLOW handle")
	}
	_, a, err := h.Recv(nil)
	if err != nil {
		return FlowEvent{}, err
	}
	ev := addressEvent(&a)
	// WINDIVERT_DATA_FLOW starts at offset 16.
	pid := binary.LittleEndian.Uint32(a.Raw[32:36])
	local, err := formatAddress(a.Raw[36:52])
	if err != nil {
		return FlowEvent{}, fmt.Errorf("local flow address: %w", err)
	}
	remote, err := formatAddress(a.Raw[52:68])
	if err != nil {
		return FlowEvent{}, fmt.Errorf("remote flow address: %w", err)
	}
	local = local.Unmap()
	remote = remote.Unmap()
	lp := binary.LittleEndian.Uint16(a.Raw[68:70])
	rp := binary.LittleEndian.Uint16(a.Raw[70:72])
	proto := a.Raw[72]
	p := ProcessInfo(pid)
	return FlowEvent{Event: ev, Key: flow.Key{Proto: proto, Local: local, Remote: remote, LocalPort: lp, RemotePort: rp}, Process: p}, nil
}

func formatAddress(raw []byte) (netip.Addr, error) {
	if len(raw) < 16 {
		return netip.Addr{}, errors.New("short address")
	}
	var out [64]byte
	r, _, e := procFormatIPv6.Call(uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	if r == 0 {
		if e == syscall.Errno(0) {
			e = errors.New("WinDivertHelperFormatIPv6Address failed")
		}
		return netip.Addr{}, e
	}
	n := 0
	for n < len(out) && out[n] != 0 {
		n++
	}
	a, err := netip.ParseAddr(string(out[:n]))
	if err != nil {
		return netip.Addr{}, err
	}
	return a, nil
}

func ProcessInfo(pid uint32) flow.Process {
	const processQueryLimitedInformation = 0x1000
	h, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return flow.Process{PID: pid}
	}
	defer procCloseHandle.Call(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return flow.Process{PID: pid}
	}
	path := syscall.UTF16ToString(buf[:n])
	return flow.NormalizeProcess(flow.Process{PID: pid, Path: path, Name: filepath.Base(strings.ReplaceAll(path, "/", "\\"))})
}

func DefaultPriority() int16 { return priorityDefault }
