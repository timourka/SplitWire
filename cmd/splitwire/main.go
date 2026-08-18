package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"splitwire/internal/browserproxy"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/winutil"
)

const version = "1.1.1"

func main() {
	if runtime.GOOS != "windows" {
		fmt.Println("SplitWire runtime works on Windows only.")
		return
	}
	dir, err := winutil.AppDir()
	if err != nil {
		fatalWait(err)
		return
	}
	_ = os.Chdir(dir)
	if !winutil.IsAdmin() {
		fmt.Println("SplitWire needs Administrator rights for packet interception. Requesting elevation...")
		if err := winutil.RelaunchElevated(); err != nil {
			fatalWait(err)
		}
		return
	}
	fmt.Println("Checking WinDivert runtime...")
	if err := winutil.EnsureAssets(dir); err != nil {
		fatalWait(fmt.Errorf("WinDivert runtime: %w", err))
		return
	}

	cfgPath := configPath(dir)
	if cfgPath == "" {
		fatalWait(fmt.Errorf("no WireGuard configuration selected"))
		return
	}
	defaultPath := findDefaultConfig(dir)
	cfg, err := config.Load(cfgPath, defaultPath)
	if err != nil {
		fatalWait(fmt.Errorf("load %s: %w", cfgPath, err))
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "last-config.txt"), []byte(cfgPath+"\n"), 0600)

	lf, err := openLog(filepath.Join(dir, "splitwire.log"))
	if err != nil {
		fatalWait(err)
		return
	}
	defer lf.Close()
	logger := log.New(io.MultiWriter(os.Stdout, lf), "", log.LstdFlags)
	logf := func(f string, a ...any) { logger.Printf(f, a...) }

	iface, err := winutil.SelectPhysicalInterface(cfg.PhysicalInterface)
	if err != nil {
		fatalWait(err)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exePath, _ := os.Executable()
	internalName := filepath.Base(exePath)
	r, err := engine.Start(ctx, engine.Params{Config: cfg, InterfaceIndex: iface.Index, InterfaceName: iface.Name, InternalProcesses: []string{internalName}, Logf: logf})
	if err != nil {
		fatalWait(err)
		return
	}
	defer r.Close()

	// Hostname mode: the PAC contains the union of configured domain patterns.
	// The PAC itself cannot identify a process, so the local proxy resolves the
	// loopback client PID and applies the group rule again before opening the
	// upstream socket. Unauthorized app+domain pairs are explicitly DIRECT.
	var proxyMode string
	proxyPatterns := cfg.ProxyDomainPatterns()
	if len(proxyPatterns) == 0 {
		proxyMode = "not needed (no hostname-restricted groups)"
	} else {
		bp, bpErr := browserproxy.Start(ctx, proxyPatterns, r.AuthorizeProxyClient, r.DialProxy, logf)
		if bpErr != nil {
			proxyMode = "DNS/SNI fallback (local proxy failed: " + bpErr.Error() + ")"
		} else {
			defer bp.Close()
			ps, psErr := winutil.InstallSessionPAC(bp.PACURL())
			if psErr != nil {
				proxyMode = "DNS/SNI fallback (Windows proxy unchanged: " + psErr.Error() + ")"
				logf("hostname PAC mode unavailable: %v", psErr)
			} else {
				defer func() {
					if err := ps.Restore(); err != nil {
						logf("restore proxy settings: %v", err)
					}
				}()
				proxyMode = "hostname PAC proxy active at " + bp.Addr()
				logf("hostname proxy active: PAC=%s proxy=%s patterns=%d", bp.PACURL(), bp.Addr(), len(proxyPatterns))
			}
		}
	}

	fmt.Printf("\nSplitWire %s\n", version)
	fmt.Printf("WireGuard config: %s\n", cfgPath)
	if cfg.UsedDefaultRules {
		fmt.Printf("Split rules: %s (default fallback)\n", cfg.DefaultRulesPath)
	} else {
		fmt.Println("Split rules: embedded in WireGuard config")
	}
	fmt.Printf("Physical network: %s\n", r.Interface())
	fmt.Println("Groups (OR between groups; AND inside each group):")
	for _, g := range cfg.Groups {
		domains := strings.Join(g.Domains, ", ")
		if domains == "" {
			domains = "-"
		}
		fmt.Printf("  [%s] Apps={%s} Domains={%s}", g.Name, strings.Join(g.Apps, ", "), domains)
		if len(g.Networks) > 0 {
			fmt.Printf(" Networks=%d", len(g.Networks))
		}
		fmt.Println()
	}
	fmt.Printf("Hostname mode: %s\n", proxyMode)
	fmt.Println("No TUN/Wintun adapter and no Windows routes are created by SplitWire.")
	fmt.Println("Close this app or press Q + Enter to disable SplitWire.")
	fmt.Println("Press S + Enter for status.")
	printStatus(r.Status())

	commands := make(chan string, 2)
	go func() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			select {
			case commands <- strings.ToLower(strings.TrimSpace(s.Text())):
			default:
			}
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Stopping...")
			return
		case cmd := <-commands:
			switch cmd {
			case "q", "quit", "exit":
				fmt.Println("Stopping...")
				return
			case "s", "status", "":
				printStatus(r.Status())
			default:
				fmt.Println("Commands: S=status, Q=quit")
			}
		case <-ticker.C:
			printStatus(r.Status())
		}
	}
}

func findDefaultConfig(dir string) string {
	candidates := []string{
		filepath.Join(dir, "splitwire.default.conf"),
		filepath.Join(filepath.Dir(dir), "splitwire.default.conf"), // convenient for source\dist builds
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	// Return the primary location so config.Load can produce a precise error.
	return candidates[0]
}

func configPath(dir string) string {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" || args[i] == "-c" {
			if i+1 < len(args) {
				return abs(args[i+1])
			}
		}
		if !strings.HasPrefix(args[i], "-") {
			return abs(args[i])
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "last-config.txt"))
	if err == nil {
		p := strings.TrimSpace(string(b))
		if p != "" {
			if _, e := os.Stat(p); e == nil {
				return p
			}
		}
	}
	fmt.Print("Path to WireGuard .conf: ")
	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		return abs(strings.Trim(strings.TrimSpace(s.Text()), "\""))
	}
	return ""
}
func abs(p string) string {
	if a, e := filepath.Abs(p); e == nil {
		return a
	}
	return p
}

func printStatus(s engine.Status) {
	hs := "not established yet"
	if !s.LastHandshake.IsZero() {
		hs = s.LastHandshake.Format("15:04:05") + " (" + time.Since(s.LastHandshake).Round(time.Second).String() + " ago)"
	}
	fmt.Printf("[status] captured=%d tunnel=%d bypass=%d dropped=%d | WG tx=%s rx=%s | learnedIPs=%d | proc=%d/%d discovery=%d domain=%d sni=%d quicFallback=%d reconnects=%d proxyWG=%d proxyDirect=%d | handshake=%s\n", s.Captured, s.Tunneled, s.Bypassed, s.Dropped, humanBytes(s.WGTxBytes), humanBytes(s.WGRxBytes), s.DomainIPs, s.ProcessResolved, s.ProcessMissed, s.DiscoveryPackets, s.DomainMatches, s.SNILearned, s.QUICSuppressed, s.Reconnects, s.ProxyTunnel, s.ProxyDirect, hs)
}
func humanBytes(n uint64) string {
	const k = 1024
	if n < k {
		return fmt.Sprintf("%d B", n)
	}
	if n < k*k {
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	if n < k*k*k {
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	}
	return fmt.Sprintf("%.1f GiB", float64(n)/(k*k*k))
}

var logMu sync.Mutex

func openLog(path string) (*os.File, error) {
	logMu.Lock()
	defer logMu.Unlock()
	if st, err := os.Stat(path); err == nil && st.Size() > 5*1024*1024 {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}
func fatalWait(err error) {
	fmt.Printf("\nERROR: %v\n", err)
	fmt.Println("Press Enter to close.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
