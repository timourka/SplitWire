package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"splitwire/internal/browserproxy"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/winutil"
)

// Logf is deliberately compatible with log.Printf and engine.Logf.
type Logf func(string, ...any)

type Options struct {
	ConfigPath        string
	AppDir            string
	InternalProcesses []string
	Logf              Logf
}

type Info struct {
	ConfigPath       string
	RuleSource       string
	UsedDefaultRules bool
	Endpoint         string
	Interface        string
	HostnameMode     string
	Groups           []config.Group
	MTU              int
}

type Session struct {
	mu        sync.RWMutex
	info      Info
	runner    *engine.Runner
	proxy     *browserproxy.Server
	proxySess *winutil.ProxySession
	cancel    context.CancelFunc
	closeOnce sync.Once
	logf      Logf
}

// FindDefaultConfig returns the same fallback locations used by the portable
// layout and by source builds. The first path is also returned when the file is
// absent so config.Load can produce a useful error message.
func FindDefaultConfig(dir string) string {
	candidates := []string{
		filepath.Join(dir, "splitwire.default.conf"),
		filepath.Join(filepath.Dir(dir), "splitwire.default.conf"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return candidates[0]
}

func Inspect(configPath, appDir string) (Info, error) {
	configPath = abs(strings.TrimSpace(configPath))
	if configPath == "" {
		return Info{}, errors.New("WireGuard config path is empty")
	}
	cfg, err := config.Load(configPath, FindDefaultConfig(appDir))
	if err != nil {
		return Info{}, err
	}
	ruleSource := configPath
	if cfg.UsedDefaultRules {
		ruleSource = cfg.DefaultRulesPath
	}
	return Info{
		ConfigPath:       configPath,
		RuleSource:       ruleSource,
		UsedDefaultRules: cfg.UsedDefaultRules,
		Endpoint:         cfg.Peer.Endpoint,
		Groups:           cloneGroups(cfg.Groups),
		MTU:              cfg.MTU,
	}, nil
}

func Start(parent context.Context, o Options) (*Session, error) {
	if parent == nil {
		parent = context.Background()
	}
	if strings.TrimSpace(o.AppDir) == "" {
		return nil, errors.New("application directory is empty")
	}
	configPath := abs(strings.TrimSpace(o.ConfigPath))
	if configPath == "" {
		return nil, errors.New("WireGuard config path is empty")
	}

	cfg, err := config.Load(configPath, FindDefaultConfig(o.AppDir))
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", configPath, err)
	}
	if o.Logf != nil {
		o.Logf("checking WinDivert runtime")
	}
	if err := winutil.EnsureAssets(o.AppDir); err != nil {
		return nil, fmt.Errorf("WinDivert runtime: %w", err)
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}

	iface, err := winutil.SelectPhysicalInterface(cfg.PhysicalInterface)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r, err := engine.Start(ctx, engine.Params{
		Config:            cfg,
		InterfaceIndex:    iface.Index,
		InterfaceName:     iface.Name,
		InternalProcesses: append([]string(nil), o.InternalProcesses...),
		Logf:              engine.Logf(o.Logf),
	})
	if err != nil {
		cancel()
		return nil, err
	}

	s := &Session{
		runner: r,
		cancel: cancel,
		logf:   o.Logf,
		info: Info{
			ConfigPath:       configPath,
			UsedDefaultRules: cfg.UsedDefaultRules,
			Endpoint:         cfg.Peer.Endpoint,
			Interface:        r.Interface(),
			Groups:           cloneGroups(cfg.Groups),
			MTU:              cfg.MTU,
		},
	}
	if cfg.UsedDefaultRules {
		s.info.RuleSource = cfg.DefaultRulesPath
	} else {
		s.info.RuleSource = configPath
	}

	proxyPatterns := cfg.ProxyDomainPatterns()
	if len(proxyPatterns) == 0 {
		s.info.HostnameMode = "not needed"
	} else {
		bp, bpErr := browserproxy.Start(ctx, proxyPatterns, r.AuthorizeProxyClient, r.DialProxy, browserproxy.Logf(o.Logf))
		if bpErr != nil {
			s.info.HostnameMode = "DNS/SNI fallback: " + bpErr.Error()
		} else {
			ps, psErr := winutil.InstallSessionPAC(bp.PACURL())
			if psErr != nil {
				_ = bp.Close()
				s.info.HostnameMode = "DNS/SNI fallback: " + psErr.Error()
				if o.Logf != nil {
					o.Logf("hostname PAC mode unavailable: %v", psErr)
				}
			} else {
				s.proxy = bp
				s.proxySess = ps
				s.info.HostnameMode = "PAC proxy " + bp.Addr()
				if o.Logf != nil {
					o.Logf("hostname proxy active: PAC=%s proxy=%s patterns=%d", bp.PACURL(), bp.Addr(), len(proxyPatterns))
				}
			}
		}
	}

	if err := parent.Err(); err != nil {
		_ = s.Close()
		return nil, err
	}
	_ = SaveLastConfig(o.AppDir, configPath)
	return s, nil
}

func (s *Session) Status() engine.Status {
	if s == nil || s.runner == nil {
		return engine.Status{}
	}
	return s.runner.Status()
}

func (s *Session) Info() Info {
	if s == nil {
		return Info{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.info
	out.Groups = cloneGroups(out.Groups)
	return out
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		// Restore the system PAC before shutting down the local proxy so Chrome
		// never points at a proxy that has already disappeared.
		if s.proxySess != nil {
			if err := s.proxySess.Restore(); err != nil {
				closeErr = errors.Join(closeErr, err)
				if s.logf != nil {
					s.logf("restore proxy settings: %v", err)
				}
			}
		}
		if s.proxy != nil {
			if err := s.proxy.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
		}
		if s.runner != nil {
			s.runner.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
	})
	return closeErr
}

func LoadLastConfig(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "last-config.txt"))
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(b))
	if p == "" {
		return ""
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

func SaveLastConfig(dir, path string) error {
	path = abs(strings.TrimSpace(path))
	if path == "" {
		return errors.New("empty config path")
	}
	return os.WriteFile(filepath.Join(dir, "last-config.txt"), []byte(path+"\n"), 0600)
}

func abs(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func cloneGroups(in []config.Group) []config.Group {
	out := make([]config.Group, len(in))
	for i, g := range in {
		out[i] = g
		out[i].Apps = append([]string(nil), g.Apps...)
		out[i].Domains = append([]string(nil), g.Domains...)
		out[i].Networks = append(out[i].Networks[:0:0], g.Networks...)
	}
	return out
}
