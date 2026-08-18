//go:build !windows

package windivert

import (
	"errors"
	"net/netip"
	"splitwire/internal/flow"
)

type Address struct{ Raw [80]byte }
type NetworkMeta struct{ IfIdx, SubIfIdx uint32 }
type Handle struct{}
type FlowEvent struct {
	Event   uint8
	Key     flow.Key
	Process flow.Process
}

const (
	EventFlowEstablished = 1
	EventFlowDeleted     = 2
	FlagSniff            = 1
	FlagRecvOnly         = 4
)

func OpenNetwork(string, int16, uint64) (*Handle, error) {
	return nil, errors.New("WinDivert is Windows-only")
}
func OpenFlow(string, int16) (*Handle, error) { return nil, errors.New("WinDivert is Windows-only") }
func (*Handle) Close() error                  { return nil }
func (*Handle) Recv([]byte) ([]byte, Address, error) {
	return nil, Address{}, errors.New("Windows-only")
}
func (*Handle) Send([]byte, Address) error        { return errors.New("Windows-only") }
func (*Handle) RecvFlow() (FlowEvent, error)      { return FlowEvent{}, errors.New("Windows-only") }
func CalcChecksums([]byte) error                  { return nil }
func (a Address) NetworkMeta() NetworkMeta        { return NetworkMeta{} }
func NewInboundAddress(NetworkMeta, bool) Address { return Address{} }
func ProcessInfo(pid uint32) flow.Process         { return flow.Process{PID: pid} }
func DefaultPriority() int16                      { return 0 }

var _ = netip.Addr{}
