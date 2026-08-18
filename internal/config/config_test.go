package config

import (
	"strings"
	"testing"
)

const testWG = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.66.66.20/32

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

const testDefaults = `[SplitWire]
MTU = 1380
DNSRefreshSeconds = 60

[Group "Messengers"]
Apps = Discord.exe, Telegram.exe
Domains = *

[Group "AI"]
Apps = chrome.exe, firefox.exe, msedge.exe
Domains = chatgpt.com, *.chatgpt.com, openai.com, *.openai.com

[Group "YouTube"]
Apps = *
Domains = youtube.com, *.youtube.com, *.googlevideo.com
`

func TestDefaultFallbackGroups(t *testing.T) {
	cfg, err := LoadFromData([]byte(testWG), []byte(testDefaults))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UsedDefaultRules {
		t.Fatal("expected default rules fallback")
	}
	if len(cfg.Groups) != 3 {
		t.Fatalf("groups=%d", len(cfg.Groups))
	}
	if cfg.Groups[0].Name != "Messengers" || len(cfg.Groups[0].Apps) != 2 || !cfg.Groups[0].DomainsAll() {
		t.Fatalf("bad first group: %+v", cfg.Groups[0])
	}
	if !cfg.Groups[2].AppsAll() {
		t.Fatalf("YouTube should be global: %+v", cfg.Groups[2])
	}
}

func TestEmbeddedGroupsReplaceDefaults(t *testing.T) {
	wg := testWG + `
[SplitWire]
MTU = 1300

[Group "Only custom"]
Apps = foo.exe
Domains = example.com, *.example.com
`
	cfg, err := LoadFromData([]byte(wg), []byte(testDefaults))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UsedDefaultRules {
		t.Fatal("embedded rules must suppress default fallback")
	}
	if cfg.MTU != 1300 || len(cfg.Groups) != 1 || cfg.Groups[0].Name != "Only custom" {
		t.Fatalf("bad custom config: %+v", cfg)
	}
}

func TestDomainPatternSemantics(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"chatgpt.com", "chatgpt.com", true},
		{"chatgpt.com", "www.chatgpt.com", false},
		{"*.chatgpt.com", "www.chatgpt.com", true},
		{"*.chatgpt.com", "chatgpt.com", false},
		{"*.chatgpt.com", "evilchatgpt.com", false},
		{"*", "anything.example", true},
	}
	for _, tc := range cases {
		if got := MatchDomainPattern(tc.pattern, tc.host); got != tc.want {
			t.Fatalf("MatchDomainPattern(%q,%q)=%v want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestInvalidWildcardRejected(t *testing.T) {
	wg := testWG + `
[SplitWire]
[Group "bad"]
Apps = chrome.exe
Domains = chat*gpt.com
`
	_, err := LoadFromData([]byte(wg), nil)
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard validation error, got %v", err)
	}
}

func TestProxyPatternsExcludeCatchAll(t *testing.T) {
	cfg, err := LoadFromData([]byte(testWG), []byte(testDefaults))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.ProxyDomainPatterns()
	for _, x := range p {
		if x == "*" {
			t.Fatal("catch-all Domains=* must never enter PAC")
		}
	}
	if len(p) == 0 {
		t.Fatal("expected hostname patterns")
	}
}
