//go:build !windows

package winutil

import "errors"

var ErrExistingProxy = errors.New("existing Windows proxy/PAC configuration detected")

type ProxySession struct{}

func InstallSessionPAC(string) (*ProxySession, error) { return nil, errors.New("Windows only") }
func (*ProxySession) Restore() error                  { return nil }
