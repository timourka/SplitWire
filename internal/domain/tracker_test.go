package domain

import (
	"net/netip"
	"testing"
	"time"

	"splitwire/internal/config"
)

func TestTrackerGroupIsolation(t *testing.T) {
	groups := []config.Group{
		{Name: "AI", Apps: []string{"chrome.exe"}, Domains: []string{"chatgpt.com", "*.chatgpt.com"}},
		{Name: "YouTube", Apps: []string{"*"}, Domains: []string{"youtube.com", "*.youtube.com"}},
	}
	tr := New(groups)
	if !tr.NameMatches("cdn.chatgpt.com") || tr.NameMatches("example.com") {
		t.Fatal("name matching failed")
	}
	ip := netip.MustParseAddr("1.2.3.4")
	matched := tr.AddForName("cdn.chatgpt.com", ip, time.Minute)
	if len(matched) != 1 || matched[0] != 0 {
		t.Fatalf("matched groups=%v", matched)
	}
	if !tr.ContainsGroup(ip, 0) || tr.ContainsGroup(ip, 1) {
		t.Fatal("IP leaked between groups")
	}
	tr.AddForName("www.youtube.com", ip, time.Minute)
	if !tr.ContainsGroup(ip, 0) || !tr.ContainsGroup(ip, 1) {
		t.Fatal("same IP should be able to belong to multiple groups")
	}
}

func TestWildcardDoesNotMatchRoot(t *testing.T) {
	tr := New([]config.Group{{Name: "x", Apps: []string{"*"}, Domains: []string{"*.example.com"}}})
	if tr.NameMatches("example.com") {
		t.Fatal("*.example.com must not match example.com")
	}
	if !tr.NameMatches("a.example.com") {
		t.Fatal("wildcard subdomain should match")
	}
}
