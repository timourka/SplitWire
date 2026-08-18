//go:build !windows

package engine

import (
	"context"
	"errors"
	"net"
	"splitwire/internal/config"
	"time"
)

type Logf func(string, ...any)
type Params struct {
	Config            *config.Config
	InterfaceIndex    uint32
	InterfaceName     string
	InternalProcesses []string
	Logf              Logf
}
type Status struct {
	Captured, Tunneled, Bypassed, Dropped, WGTxBytes, WGRxBytes                                                                       uint64
	DomainIPs                                                                                                                         int
	LastHandshake                                                                                                                     time.Time
	ProcessResolved, ProcessMissed, DiscoveryPackets, DomainMatches, SNILearned, QUICSuppressed, Reconnects, ProxyTunnel, ProxyDirect uint64
}
type Runner struct{}

func Start(context.Context, Params) (*Runner, error) {
	return nil, errors.New("SplitWire runtime is Windows-only")
}
func (*Runner) Close()            {}
func (*Runner) Status() Status    { return Status{} }
func (*Runner) Interface() string { return "" }
func (*Runner) AuthorizeProxyClient(clientAddr, proxyAddr, host string) (bool, string) {
	return false, "windows-only"
}
func (*Runner) DialProxy(ctx context.Context, network, address string, tunnel bool) (net.Conn, error) {
	return nil, errors.New("SplitWire runtime is Windows-only")
}
