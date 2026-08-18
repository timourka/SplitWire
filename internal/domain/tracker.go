package domain

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"splitwire/internal/config"
)

type Tracker struct {
	mu     sync.RWMutex
	ips    map[netip.Addr]map[int]time.Time // IP -> group index -> expiry
	groups []config.Group
	now    func() time.Time
}

func New(groups []config.Group) *Tracker {
	cp := make([]config.Group, len(groups))
	copy(cp, groups)
	return &Tracker{ips: map[netip.Addr]map[int]time.Time{}, groups: cp, now: time.Now}
}

func (t *Tracker) NameGroups(name string) []int {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	out := make([]int, 0, 2)
	for i, g := range t.groups {
		if g.DomainsAll() {
			continue
		}
		if g.MatchesDomain(name) {
			out = append(out, i)
		}
	}
	return out
}

func (t *Tracker) NameMatches(name string) bool { return len(t.NameGroups(name)) != 0 }

func (t *Tracker) GroupsForNames(names []string) []int {
	seen := map[int]struct{}{}
	for _, name := range names {
		for _, i := range t.NameGroups(name) {
			seen[i] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	return out
}

func clampTTL(ttl time.Duration) time.Duration {
	if ttl < 10*time.Second {
		return 10 * time.Second
	}
	if ttl > 24*time.Hour {
		return 24 * time.Hour
	}
	return ttl
}

func (t *Tracker) AddGroups(ip netip.Addr, groups []int, ttl time.Duration) {
	if !ip.IsValid() || len(groups) == 0 {
		return
	}
	ip = ip.Unmap()
	exp := t.now().Add(clampTTL(ttl))
	t.mu.Lock()
	m := t.ips[ip]
	if m == nil {
		m = map[int]time.Time{}
		t.ips[ip] = m
	}
	for _, i := range groups {
		if i < 0 || i >= len(t.groups) {
			continue
		}
		if old, ok := m[i]; !ok || old.Before(exp) {
			m[i] = exp
		}
	}
	t.mu.Unlock()
}

func (t *Tracker) AddForName(name string, ip netip.Addr, ttl time.Duration) []int {
	groups := t.NameGroups(name)
	t.AddGroups(ip, groups, ttl)
	return groups
}

func (t *Tracker) ContainsGroup(ip netip.Addr, group int) bool {
	ip = ip.Unmap()
	now := t.now()
	t.mu.RLock()
	m := t.ips[ip]
	exp, ok := m[group]
	t.mu.RUnlock()
	return ok && now.Before(exp)
}

func (t *Tracker) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	now := t.now()
	t.mu.RLock()
	m := t.ips[ip]
	for _, exp := range m {
		if now.Before(exp) {
			t.mu.RUnlock()
			return true
		}
	}
	t.mu.RUnlock()
	return false
}

func (t *Tracker) Sweep() {
	now := t.now()
	t.mu.Lock()
	for ip, m := range t.ips {
		for gi, exp := range m {
			if !now.Before(exp) {
				delete(m, gi)
			}
		}
		if len(m) == 0 {
			delete(t.ips, ip)
		}
	}
	t.mu.Unlock()
}

func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ips)
}

// ResolveBootstrap resolves the exact name or wildcard base of each configured
// domain pattern. It is only a seed/fallback; PAC, DNS and TLS SNI discovery
// remain authoritative for CDN addresses learned at runtime.
func (t *Tracker) ResolveBootstrap(ctx context.Context, ttl time.Duration) {
	type item struct {
		name  string
		group int
	}
	var items []item
	seen := map[string]struct{}{}
	for gi, g := range t.groups {
		if g.DomainsAll() {
			continue
		}
		for _, p := range g.Domains {
			name := strings.TrimPrefix(p, "*.")
			if name == "" || name == "*" {
				continue
			}
			key := strings.ToLower(name) + "\x00" + string(rune(gi))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			items = append(items, item{name: name, group: gi})
		}
	}
	r := net.DefaultResolver
	for _, it := range items {
		ips, err := r.LookupNetIP(ctx, "ip", it.name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			t.AddGroups(ip, []int{it.group}, ttl)
		}
	}
}
