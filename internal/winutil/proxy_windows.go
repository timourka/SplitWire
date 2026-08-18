//go:build windows

package winutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var ErrExistingProxy = errors.New("existing Windows proxy/PAC configuration detected")

type proxySnapshot struct {
	HasAutoConfigURL bool   `json:"hasAutoConfigURL"`
	AutoConfigURL    string `json:"autoConfigURL"`
	ProxyEnable      int    `json:"proxyEnable"`
	ProxyServer      string `json:"proxyServer"`
}

type ProxySession struct {
	snap      proxySnapshot
	installed bool
}

var (
	modWininet             = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = modWininet.NewProc("InternetSetOptionW")
)

// InstallSessionPAC temporarily points the current user's WinINET/Chrome proxy
// settings at SplitWire's local PAC endpoint. It refuses to override an
// existing explicit proxy or PAC. Restore must be called on normal shutdown.
func InstallSessionPAC(pacURL string) (*ProxySession, error) {
	pacURL = strings.TrimSpace(pacURL)
	if pacURL == "" {
		return nil, errors.New("empty PAC URL")
	}
	snap, err := readProxySnapshot()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(snap.AutoConfigURL) != "" {
		if isSplitWirePAC(snap.AutoConfigURL) {
			if pacAlive(snap.AutoConfigURL) {
				return nil, fmt.Errorf("%w: another SplitWire PAC appears active at %q", ErrExistingProxy, snap.AutoConfigURL)
			}
			// A previous SplitWire process was interrupted before Restore. SplitWire
			// only installs PAC when no prior PAC existed, so this stale local URL can
			// safely be reclaimed and later removed on normal shutdown.
			snap.HasAutoConfigURL = false
			snap.AutoConfigURL = ""
		} else {
			return nil, fmt.Errorf("%w: AutoConfigURL=%q", ErrExistingProxy, snap.AutoConfigURL)
		}
	}
	if snap.ProxyEnable != 0 {
		return nil, fmt.Errorf("%w: ProxyEnable=%d ProxyServer=%q", ErrExistingProxy, snap.ProxyEnable, snap.ProxyServer)
	}
	q := psQuote(pacURL)
	_, err = powershell(`$p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty -Path $p -Name AutoConfigURL -Value '` + q + `' -Type String`)
	if err != nil {
		return nil, fmt.Errorf("set AutoConfigURL: %w", err)
	}
	notifyProxyChange()
	return &ProxySession{snap: snap, installed: true}, nil
}

func (s *ProxySession) Restore() error {
	if s == nil || !s.installed {
		return nil
	}
	var script string
	if s.snap.HasAutoConfigURL {
		script = `$p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty -Path $p -Name AutoConfigURL -Value '` + psQuote(s.snap.AutoConfigURL) + `' -Type String`
	} else {
		script = `$p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Remove-ItemProperty -Path $p -Name AutoConfigURL -ErrorAction SilentlyContinue`
	}
	_, err := powershell(script)
	notifyProxyChange()
	s.installed = false
	if err != nil {
		return fmt.Errorf("restore Windows proxy settings: %w", err)
	}
	return nil
}

func readProxySnapshot() (proxySnapshot, error) {
	script := `$p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $x=Get-ItemProperty -Path $p; $has=($x.PSObject.Properties.Name -contains 'AutoConfigURL'); $pe=0; if($x.PSObject.Properties.Name -contains 'ProxyEnable'){$pe=[int]$x.ProxyEnable}; $ps=''; if($x.PSObject.Properties.Name -contains 'ProxyServer'){$ps=[string]$x.ProxyServer}; [pscustomobject]@{hasAutoConfigURL=$has;autoConfigURL=$(if($has){[string]$x.AutoConfigURL}else{''});proxyEnable=$pe;proxyServer=$ps}|ConvertTo-Json -Compress`
	out, err := powershell(script)
	if err != nil {
		return proxySnapshot{}, fmt.Errorf("read Windows proxy settings: %w", err)
	}
	var s proxySnapshot
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return proxySnapshot{}, fmt.Errorf("parse Windows proxy settings %q: %w", out, err)
	}
	return s, nil
}

func isSplitWirePAC(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return u.Scheme == "http" && host == "127.0.0.1" && u.Path == "/proxy.pac"
}

func pacAlive(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", u.Host, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func notifyProxyChange() {
	// INTERNET_OPTION_SETTINGS_CHANGED=39, INTERNET_OPTION_REFRESH=37.
	procInternetSetOptionW.Call(0, 39, 0, 0)
	procInternetSetOptionW.Call(0, 37, 0, 0)
	// Keep unsafe imported in this Windows-only file across Go versions where
	// syscall.NewLazyDLL signatures may otherwise optimize all pointer usage out.
	_ = unsafe.Pointer(nil)
}
