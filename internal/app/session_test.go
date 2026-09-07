package app

import (
	"os"
	"path/filepath"
	"testing"
)

const testWG = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 192.0.2.1:51820
`

const testRules = `[SplitWire]
MTU = 1380

[Group "Test"]
Apps = test.exe
Domains = example.com
`

func TestInspectUsesDefaultRules(t *testing.T) {
	d := t.TempDir()
	wg := filepath.Join(d, "wg.conf")
	def := filepath.Join(d, "splitwire.default.conf")
	if err := os.WriteFile(wg, []byte(testWG), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(def, []byte(testRules), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(wg, d)
	if err != nil {
		t.Fatal(err)
	}
	if !info.UsedDefaultRules || info.RuleSource != def {
		t.Fatalf("unexpected rules source: %+v", info)
	}
	if len(info.Groups) != 1 || info.Groups[0].Name != "Test" {
		t.Fatalf("unexpected groups: %+v", info.Groups)
	}
}

func TestSaveLoadLastConfig(t *testing.T) {
	d := t.TempDir()
	wg := filepath.Join(d, "wg.conf")
	if err := os.WriteFile(wg, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveLastConfig(d, wg); err != nil {
		t.Fatal(err)
	}
	if got := LoadLastConfig(d); got != wg {
		t.Fatalf("LoadLastConfig=%q want %q", got, wg)
	}
}
