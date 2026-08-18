package policy

import (
	"net/netip"
	"testing"
	"time"

	"splitwire/internal/config"
	"splitwire/internal/domain"
	"splitwire/internal/flow"
)

func groupConfig() config.Config {
	return config.Config{Groups: []config.Group{
		{Name: "Messengers", Apps: []string{"Discord.exe", "Telegram.exe"}, Domains: []string{"*"}},
		{Name: "AI", Apps: []string{"chrome.exe", "firefox.exe", "msedge.exe"}, Domains: []string{"chatgpt.com", "*.chatgpt.com", "openai.com", "*.openai.com"}},
		{Name: "YouTube", Apps: []string{"*"}, Domains: []string{"youtube.com", "*.youtube.com", "*.googlevideo.com"}},
	}}
}

func TestGroupORAndInternalAND(t *testing.T) {
	cfg := groupConfig()
	tr := domain.New(cfg.Groups)
	aiIP := netip.MustParseAddr("198.51.100.7")
	ytIP := netip.MustParseAddr("203.0.113.9")
	tr.AddGroups(aiIP, []int{1}, time.Hour)
	tr.AddGroups(ytIP, []int{2}, time.Hour)
	p := New(&cfg, tr)

	cases := []struct {
		name string
		proc flow.Process
		dst  netip.Addr
		want bool
	}{
		{"discord any destination", flow.Process{Name: "Discord.exe"}, netip.MustParseAddr("8.8.8.8"), true},
		{"telegram any destination", flow.Process{Name: "Telegram.exe"}, netip.MustParseAddr("1.1.1.1"), true},
		{"chatgpt chrome", flow.Process{Name: "chrome.exe"}, aiIP, true},
		{"chatgpt firefox", flow.Process{Name: "firefox.exe"}, aiIP, true},
		{"chatgpt wrong app", flow.Process{Name: "notepad.exe"}, aiIP, false},
		{"youtube any app", flow.Process{Name: "notepad.exe"}, ytIP, true},
		{"unrelated", flow.Process{Name: "notepad.exe"}, netip.MustParseAddr("192.0.2.1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Decide(tc.proc, tc.dst).Tunnel; got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDecideHostAndGlobalGroup(t *testing.T) {
	cfg := groupConfig()
	p := New(&cfg, domain.New(cfg.Groups))
	if !p.DecideHost(flow.Process{Name: "chrome.exe"}, "chatgpt.com").Tunnel {
		t.Fatal("Chrome+ChatGPT should tunnel")
	}
	if p.DecideHost(flow.Process{Name: "notepad.exe"}, "chatgpt.com").Tunnel {
		t.Fatal("Notepad+ChatGPT must not match AI group")
	}
	if !p.DecideHost(flow.Process{Name: "notepad.exe"}, "www.youtube.com").Tunnel {
		t.Fatal("YouTube Apps=* should match any process")
	}
}

func TestInternalRecognitionOnly(t *testing.T) {
	cfg := groupConfig()
	p := NewWithInternal(&cfg, domain.New(cfg.Groups), []string{"SplitWire.exe"})
	if !p.IsInternal(flow.Process{Name: "SplitWire.exe"}) {
		t.Fatal("internal process not recognized")
	}
	// Internal routing is decided by the pre-connect proxy route table in the
	// engine, not by an implicit 'all SplitWire TCP' policy rule.
	if p.Decide(flow.Process{Name: "SplitWire.exe"}, netip.MustParseAddr("192.0.2.55")).Tunnel {
		t.Fatal("internal process must not be implicitly tunneled")
	}
}
