package config

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	PersistentKeepalive int
}

type Group struct {
	Name     string
	Apps     []string
	Domains  []string
	Networks []netip.Prefix
}

type Config struct {
	PrivateKey        string
	Addresses         []netip.Prefix
	Peer              Peer
	Groups            []Group
	PhysicalInterface string
	MTU               int
	DNSRefreshSeconds int
	UsedDefaultRules  bool
	DefaultRulesPath  string
}

// Defaults contains only runtime defaults. Split routing rules intentionally
// live in splitwire.default.conf rather than being hard-coded in the binary.
func Defaults() Config {
	return Config{MTU: 1380, DNSRefreshSeconds: 60}
}

// Load reads a normal WireGuard config and SplitWire rules. If the WireGuard
// config has no [SplitWire] or [Group "..."] sections, the SplitWire sections
// are loaded from defaultRulesPath.
func Load(path, defaultRulesPath string) (*Config, error) {
	wgData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Defaults()
	customSplit := hasSplitSections(wgData)
	if !customSplit {
		if strings.TrimSpace(defaultRulesPath) == "" {
			return nil, errors.New("WireGuard config has no SplitWire rules and no default config path was provided")
		}
		defaultData, err := os.ReadFile(defaultRulesPath)
		if err != nil {
			return nil, fmt.Errorf("WireGuard config has no SplitWire rules; load default config %s: %w", defaultRulesPath, err)
		}
		if err := parseInto(bufio.NewScanner(bytes.NewReader(defaultData)), &cfg, false); err != nil {
			return nil, fmt.Errorf("default config %s: %w", defaultRulesPath, err)
		}
		cfg.UsedDefaultRules = true
		cfg.DefaultRulesPath = defaultRulesPath
	}
	if err := parseInto(bufio.NewScanner(bytes.NewReader(wgData)), &cfg, true); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadFromData is used by tests and tooling. It follows the same fallback
// semantics as Load without touching the filesystem.
func LoadFromData(wgData, defaultData []byte) (*Config, error) {
	cfg := Defaults()
	if !hasSplitSections(wgData) {
		if len(defaultData) == 0 {
			return nil, errors.New("WireGuard config has no SplitWire rules and default config is empty")
		}
		if err := parseInto(bufio.NewScanner(bytes.NewReader(defaultData)), &cfg, false); err != nil {
			return nil, fmt.Errorf("default config: %w", err)
		}
		cfg.UsedDefaultRules = true
	}
	if err := parseInto(bufio.NewScanner(bytes.NewReader(wgData)), &cfg, true); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func hasSplitSections(data []byte) bool {
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(stripComment(s.Text()))
		if len(line) < 2 || line[0] != '[' || line[len(line)-1] != ']' {
			continue
		}
		raw := strings.TrimSpace(line[1 : len(line)-1])
		low := strings.ToLower(raw)
		if low == "splitwire" || low == "group" || strings.HasPrefix(low, "group ") || strings.HasPrefix(low, "group\t") {
			return true
		}
	}
	return false
}

type sectionKind uint8

const (
	sectionOther sectionKind = iota
	sectionInterface
	sectionPeer
	sectionSplitWire
	sectionGroup
)

func parseSection(raw string) (sectionKind, string, error) {
	raw = strings.TrimSpace(raw)
	low := strings.ToLower(raw)
	switch low {
	case "interface":
		return sectionInterface, "", nil
	case "peer":
		return sectionPeer, "", nil
	case "splitwire":
		return sectionSplitWire, "", nil
	}
	if low == "group" || strings.HasPrefix(low, "group ") || strings.HasPrefix(low, "group\t") {
		rest := strings.TrimSpace(raw[len("group"):])
		if rest == "" {
			return sectionOther, "", errors.New("group section requires a name, e.g. [Group \"AI\"]")
		}
		name := rest
		if strings.HasPrefix(rest, "\"") {
			u, err := strconv.Unquote(rest)
			if err != nil {
				return sectionOther, "", fmt.Errorf("invalid group name %q: %w", rest, err)
			}
			name = u
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return sectionOther, "", errors.New("group name cannot be empty")
		}
		return sectionGroup, name, nil
	}
	return sectionOther, "", nil
}

func parseInto(s *bufio.Scanner, cfg *Config, allowWireGuard bool) error {
	kind := sectionOther
	peerSeen := false
	groupIndex := -1
	for lineNo := 1; s.Scan(); lineNo++ {
		line := strings.TrimSpace(stripComment(s.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			var err error
			kind, _, err = parseSection(strings.TrimSpace(line[1 : len(line)-1]))
			if err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			groupIndex = -1
			if kind == sectionGroup {
				_, name, _ := parseSection(strings.TrimSpace(line[1 : len(line)-1]))
				cfg.Groups = append(cfg.Groups, Group{Name: name})
				groupIndex = len(cfg.Groups) - 1
			}
			if allowWireGuard && kind == sectionPeer {
				if peerSeen {
					return fmt.Errorf("line %d: SplitWire supports exactly one [Peer]", lineNo)
				}
				peerSeen = true
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d: expected key = value", lineNo)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch kind {
		case sectionInterface:
			if !allowWireGuard {
				continue
			}
			switch k {
			case "privatekey":
				cfg.PrivateKey = v
			case "address":
				for _, p := range splitList(v) {
					pr, err := netip.ParsePrefix(p)
					if err != nil {
						return fmt.Errorf("line %d: Address %q: %w", lineNo, p, err)
					}
					cfg.Addresses = append(cfg.Addresses, pr)
				}
			}
		case sectionPeer:
			if !allowWireGuard {
				continue
			}
			switch k {
			case "publickey":
				cfg.Peer.PublicKey = v
			case "presharedkey":
				cfg.Peer.PresharedKey = v
			case "endpoint":
				cfg.Peer.Endpoint = v
			case "persistentkeepalive":
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("line %d: PersistentKeepalive: %w", lineNo, err)
				}
				cfg.Peer.PersistentKeepalive = n
			}
		case sectionSplitWire:
			switch k {
			case "physicalinterface", "interface":
				cfg.PhysicalInterface = v
			case "mtu":
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("line %d: MTU: %w", lineNo, err)
				}
				cfg.MTU = n
			case "dnsrefreshseconds":
				n, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("line %d: DNSRefreshSeconds: %w", lineNo, err)
				}
				cfg.DNSRefreshSeconds = n
			}
		case sectionGroup:
			if groupIndex < 0 || groupIndex >= len(cfg.Groups) {
				return fmt.Errorf("line %d: internal group parser state", lineNo)
			}
			g := &cfg.Groups[groupIndex]
			switch k {
			case "apps", "applications":
				g.Apps = splitList(v)
			case "domains":
				g.Domains = lowerList(v)
			case "networks", "ips", "addresses":
				g.Networks = nil
				for _, p := range splitList(v) {
					pr, err := netip.ParsePrefix(p)
					if err != nil {
						return fmt.Errorf("line %d: Network %q: %w", lineNo, p, err)
					}
					g.Networks = append(g.Networks, pr.Masked())
				}
			}
		}
	}
	return s.Err()
}

func (c *Config) Validate() error {
	if err := validWGKey(c.PrivateKey); err != nil {
		return fmt.Errorf("Interface.PrivateKey: %w", err)
	}
	if err := validWGKey(c.Peer.PublicKey); err != nil {
		return fmt.Errorf("Peer.PublicKey: %w", err)
	}
	if c.Peer.PresharedKey != "" {
		if err := validWGKey(c.Peer.PresharedKey); err != nil {
			return fmt.Errorf("Peer.PresharedKey: %w", err)
		}
	}
	if strings.TrimSpace(c.Peer.Endpoint) == "" {
		return errors.New("Peer.Endpoint is required")
	}
	if len(c.Addresses) == 0 {
		return errors.New("Interface.Address is required")
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("MTU %d is unreasonable", c.MTU)
	}
	if c.DNSRefreshSeconds < 10 {
		c.DNSRefreshSeconds = 10
	}
	if len(c.Groups) == 0 {
		return errors.New("no [Group \"...\"] split rules configured")
	}
	seen := make(map[string]struct{}, len(c.Groups))
	for i := range c.Groups {
		g := &c.Groups[i]
		g.Name = strings.TrimSpace(g.Name)
		if g.Name == "" {
			return fmt.Errorf("group #%d has empty name", i+1)
		}
		key := strings.ToLower(g.Name)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		seen[key] = struct{}{}
		g.Apps = normalizeApps(g.Apps)
		g.Domains = normalizeDomains(g.Domains)
		if len(g.Apps) == 0 {
			return fmt.Errorf("group %q: Apps is required", g.Name)
		}
		if len(g.Domains) == 0 && len(g.Networks) == 0 {
			return fmt.Errorf("group %q: Domains or Networks is required", g.Name)
		}
		for _, d := range g.Domains {
			if err := validateDomainPattern(d); err != nil {
				return fmt.Errorf("group %q: domain %q: %w", g.Name, d, err)
			}
		}
	}
	return nil
}

func normalizeApps(in []string) []string {
	out := dedupe(in, false)
	for _, x := range out {
		if x == "*" {
			return []string{"*"}
		}
	}
	return out
}

func normalizeDomains(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in[i]), "."))
	}
	out := dedupe(in, true)
	for _, x := range out {
		if x == "*" {
			return []string{"*"}
		}
	}
	return out
}

func dedupe(in []string, lower bool) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if lower {
			x = strings.ToLower(x)
		}
		if x == "" {
			continue
		}
		k := strings.ToLower(x)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, x)
	}
	return out
}

func validateDomainPattern(p string) error {
	if p == "*" {
		return nil
	}
	if strings.Contains(p, "*") {
		if !strings.HasPrefix(p, "*.") || strings.Contains(p[2:], "*") || len(p) <= 2 {
			return errors.New("only '*' or a leading '*.' wildcard is supported")
		}
	}
	base := strings.TrimPrefix(p, "*.")
	if base == "" || strings.ContainsAny(base, " /\\:") || strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".") {
		return errors.New("invalid DNS name pattern")
	}
	return nil
}

func (g Group) AppsAll() bool {
	return len(g.Apps) == 1 && g.Apps[0] == "*"
}
func (g Group) DomainsAll() bool {
	return len(g.Domains) == 1 && g.Domains[0] == "*"
}

func MatchDomainPattern(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if p == "*" {
		return h != ""
	}
	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		return h != base && strings.HasSuffix(h, "."+base)
	}
	return h == p
}

func (g Group) MatchesDomain(host string) bool {
	for _, p := range g.Domains {
		if MatchDomainPattern(p, host) {
			return true
		}
	}
	return false
}

func (c *Config) ProxyDomainPatterns() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, g := range c.Groups {
		for _, p := range g.Domains {
			if p == "*" {
				continue // never turn the system PAC into a catch-all proxy
			}
			k := strings.ToLower(p)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) TunnelIPv4() (netip.Addr, bool) {
	for _, p := range c.Addresses {
		if p.Addr().Is4() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}
func (c *Config) TunnelIPv6() (netip.Addr, bool) {
	for _, p := range c.Addresses {
		if p.Addr().Is6() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func validWGKey(s string) error {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return nil
}
func DecodeKey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
func lowerList(v string) []string {
	xs := splitList(v)
	for i := range xs {
		xs[i] = strings.ToLower(strings.TrimSuffix(xs[i], "."))
	}
	return xs
}
func stripComment(s string) string {
	for i, r := range s {
		if r == '#' || r == ';' {
			return s[:i]
		}
	}
	return s
}
