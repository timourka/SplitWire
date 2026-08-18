package policy

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"splitwire/internal/config"
	"splitwire/internal/domain"
	"splitwire/internal/flow"
)

func BenchmarkDecideIndexedGroups(b *testing.B) {
	for _, n := range []int{3, 50, 500} {
		b.Run(fmt.Sprintf("groups_%d", n), func(b *testing.B) {
			groups := make([]config.Group, 0, n)
			for i := 0; i < n-1; i++ {
				groups = append(groups, config.Group{Name: fmt.Sprintf("unrelated-%d", i), Apps: []string{fmt.Sprintf("app%d.exe", i)}, Domains: []string{"*"}})
			}
			groups = append(groups, config.Group{Name: "target", Apps: []string{"chrome.exe"}, Domains: []string{"example.com"}})
			cfg := config.Config{Groups: groups}
			tr := domain.New(groups)
			ip := netip.MustParseAddr("203.0.113.9")
			tr.AddGroups(ip, []int{len(groups) - 1}, time.Hour)
			p := New(&cfg, tr)
			proc := flow.Process{Name: "chrome.exe"}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = p.Decide(proc, ip)
			}
		})
	}
}
