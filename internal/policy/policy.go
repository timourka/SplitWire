package policy

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"splitwire/internal/config"
	"splitwire/internal/domain"
	"splitwire/internal/flow"
)

type Decision struct {
	Tunnel bool
	Reason string
	Group  string
}

type Engine struct {
	cfg      *config.Config
	domains  *domain.Tracker
	internal []string

	// Application selectors are compiled once. Packet hot-path cost therefore
	// depends mostly on global Apps=* groups and groups that mention the current
	// executable, not on every unrelated group in the file.
	globalGroups []int
	byName       map[string][]int
	byPath       map[string][]int
}

func New(cfg *config.Config, domains *domain.Tracker) *Engine {
	e := &Engine{cfg: cfg, domains: domains}
	e.compileApps()
	return e
}

func NewWithInternal(cfg *config.Config, domains *domain.Tracker, internal []string) *Engine {
	e := New(cfg, domains)
	e.internal = append([]string(nil), internal...)
	return e
}

func canonPath(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "/", "\\"))
}
func canonName(s string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(strings.TrimSpace(s), "\\", "/")))
}

func (e *Engine) compileApps() {
	e.byName = map[string][]int{}
	e.byPath = map[string][]int{}
	for i, g := range e.cfg.Groups {
		if g.AppsAll() {
			e.globalGroups = append(e.globalGroups, i)
			continue
		}
		for _, app := range g.Apps {
			if strings.ContainsAny(app, "\\/") {
				k := canonPath(app)
				e.byPath[k] = append(e.byPath[k], i)
			} else {
				k := canonName(app)
				e.byName[k] = append(e.byName[k], i)
			}
		}
	}
}

func (e *Engine) candidateSlices(proc flow.Process) (global, byName, byPath []int) {
	return e.globalGroups, e.byName[canonName(proc.Name)], e.byPath[canonPath(proc.Path)]
}

func (e *Engine) groupDestinationMatches(groupIndex int, g config.Group, dst netip.Addr) bool {
	if g.DomainsAll() {
		return true
	}
	for _, n := range g.Networks {
		if n.Contains(dst) {
			return true
		}
	}
	return e.domains != nil && e.domains.ContainsGroup(dst, groupIndex)
}

func (e *Engine) decideIDs(ids []int, dst netip.Addr) Decision {
	for _, i := range ids {
		g := e.cfg.Groups[i]
		if !e.groupDestinationMatches(i, g, dst) {
			continue
		}
		return Decision{Tunnel: true, Reason: fmt.Sprintf("group:%s", g.Name), Group: g.Name}
	}
	return Decision{}
}

func (e *Engine) Decide(proc flow.Process, dst netip.Addr) Decision {
	dst = dst.Unmap()
	global, names, paths := e.candidateSlices(proc)
	if d := e.decideIDs(global, dst); d.Tunnel {
		return d
	}
	if d := e.decideIDs(names, dst); d.Tunnel {
		return d
	}
	return e.decideIDs(paths, dst)
}

// DecideHost is used by the local hostname proxy before the upstream socket is
// created. This preserves per-application domain groups even though a Windows
// PAC file itself cannot see the originating process.
func (e *Engine) decideHostIDs(ids []int, host string) Decision {
	for _, i := range ids {
		g := e.cfg.Groups[i]
		if g.DomainsAll() || !g.MatchesDomain(host) {
			continue
		}
		return Decision{Tunnel: true, Reason: fmt.Sprintf("host-group:%s", g.Name), Group: g.Name}
	}
	return Decision{}
}

func (e *Engine) DecideHost(proc flow.Process, host string) Decision {
	global, names, paths := e.candidateSlices(proc)
	if d := e.decideHostIDs(global, host); d.Tunnel {
		return d
	}
	if d := e.decideHostIDs(names, host); d.Tunnel {
		return d
	}
	return e.decideHostIDs(paths, host)
}

func (e *Engine) IsInternal(proc flow.Process) bool { return flow.Match(proc, e.internal) }

// CouldTunnelWithoutProcess reports whether a destination is selected by a
// global Apps=* group. It avoids a process-owner lookup on those packets.
func (e *Engine) CouldTunnelWithoutProcess(dst netip.Addr) bool {
	dst = dst.Unmap()
	for _, i := range e.globalGroups {
		g := e.cfg.Groups[i]
		if e.groupDestinationMatches(i, g, dst) {
			return true
		}
	}
	return false
}

// NeedsTLSDiscovery reports whether this process participates in any
// hostname-restricted group. Parsing TLS ClientHello is a fallback for apps
// that do not use the system PAC or when PAC installation is unavailable.
func (e *Engine) needsTLSIDs(ids []int) bool {
	for _, i := range ids {
		g := e.cfg.Groups[i]
		if !g.DomainsAll() && len(g.Domains) > 0 {
			return true
		}
	}
	return false
}

func (e *Engine) NeedsTLSDiscovery(proc flow.Process) bool {
	global, names, paths := e.candidateSlices(proc)
	return e.needsTLSIDs(global) || e.needsTLSIDs(names) || e.needsTLSIDs(paths)
}

// ShouldSuppressQUIC is intentionally narrower than NeedsTLSDiscovery. A
// global Apps=* hostname group must not cause the first UDP/443 packet of every
// process on the machine to be dropped. QUIC fallback is therefore used only
// for explicitly named applications.
func (e *Engine) ShouldSuppressQUIC(proc flow.Process) bool {
	// Only named/path candidates; deliberately exclude globalGroups.
	for _, i := range e.byName[canonName(proc.Name)] {
		g := e.cfg.Groups[i]
		if !g.DomainsAll() && len(g.Domains) > 0 {
			return true
		}
	}
	for _, i := range e.byPath[canonPath(proc.Path)] {
		g := e.cfg.Groups[i]
		if !g.DomainsAll() && len(g.Domains) > 0 {
			return true
		}
	}
	return false
}

func (e *Engine) domainIPIDs(ids []int, dst netip.Addr) bool {
	for _, i := range ids {
		g := e.cfg.Groups[i]
		if g.DomainsAll() {
			continue
		}
		if e.domains != nil && e.domains.ContainsGroup(dst, i) {
			return true
		}
	}
	return false
}

func (e *Engine) IsDomainIPForProcess(proc flow.Process, dst netip.Addr) bool {
	dst = dst.Unmap()
	global, names, paths := e.candidateSlices(proc)
	return e.domainIPIDs(global, dst) || e.domainIPIDs(names, dst) || e.domainIPIDs(paths, dst)
}
