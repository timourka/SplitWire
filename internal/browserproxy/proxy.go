package browserproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"splitwire/internal/config"
)

type Logf func(string, ...any)

// AuthorizeFunc decides whether host requested by the client at clientAddr
// belongs to a tunnel group for that client process. A false decision is still
// proxied, but the upstream socket is explicitly marked DIRECT by DialFunc.
type AuthorizeFunc func(clientAddr, proxyAddr, host string) (tunnel bool, reason string)

// DialFunc opens an upstream connection with an explicit route choice. On
// Windows SplitWire registers the socket before connect so the very first SYN
// follows the chosen route.
type DialFunc func(ctx context.Context, network, address string, tunnel bool) (net.Conn, error)

type limitedLogState struct {
	last       time.Time
	suppressed uint64
}

type Server struct {
	ln        net.Listener
	http      *http.Server
	patterns  []string
	authorize AuthorizeFunc
	dial      DialFunc
	logf      Logf
	closeOnce sync.Once
	logMu     sync.Mutex
	logState  map[string]limitedLogState
}

func Start(ctx context.Context, patterns []string, authorize AuthorizeFunc, dial DialFunc, logf Logf) (*Server, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		dial = func(ctx context.Context, network, address string, _ bool) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		}
	}
	s := &Server{ln: ln, patterns: normalize(patterns), authorize: authorize, dial: dial, logf: logf, logState: map[string]limitedLogState{}}
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log("hostname proxy server: %v", err)
		}
	}()
	return s, nil
}

func normalize(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		x = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(x), "."))
		if x == "" || x == "*" { // never make system PAC catch all traffic
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func (s *Server) Addr() string   { return s.ln.Addr().String() }
func (s *Server) PACURL() string { return "http://" + s.Addr() + "/proxy.pac" }

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = s.http.Shutdown(ctx)
		_ = s.ln.Close()
	})
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/proxy.pac" || r.URL.Path == "/wpad.dat") {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		_, _ = io.WriteString(w, s.PAC())
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) PAC() string {
	var cond []string
	for _, p := range s.patterns {
		if strings.HasPrefix(p, "*.") {
			base := p[2:]
			cond = append(cond, "dnsDomainIs(h, "+jsQuote("."+base)+")")
		} else {
			cond = append(cond, "h === "+jsQuote(p))
		}
	}
	expr := "false"
	if len(cond) > 0 {
		expr = strings.Join(cond, " || ")
	}
	return fmt.Sprintf("function FindProxyForURL(url, host) { var h=(host||'').toLowerCase(); if (%s) return 'PROXY %s; DIRECT'; return 'DIRECT'; }\n", expr, s.Addr())
}

func jsQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return "'" + s + "'"
}

func (s *Server) matchesHost(host string) bool {
	for _, p := range s.patterns {
		if config.MatchDomainPattern(p, host) {
			return true
		}
	}
	return false
}

func splitTarget(authority string, defaultPort string) (host, target string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", fmt.Errorf("empty target")
	}
	h, p, e := net.SplitHostPort(authority)
	if e != nil {
		if strings.Contains(authority, ":") && strings.Count(authority, ":") > 1 {
			return "", "", e
		}
		h, p = authority, defaultPort
	}
	if p == "" {
		p = defaultPort
	}
	if _, e := strconv.Atoi(p); e != nil {
		return "", "", fmt.Errorf("bad port %q", p)
	}
	return strings.Trim(h, "[]"), net.JoinHostPort(strings.Trim(h, "[]"), p), nil
}

func (s *Server) route(clientAddr, host string) (bool, string) {
	if s.authorize == nil {
		return true, "default"
	}
	return s.authorize(clientAddr, s.Addr(), host)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, target, err := splitTarget(r.Host, "443")
	if err != nil || !s.matchesHost(host) {
		http.Error(w, "SplitWire proxy only accepts configured domains", http.StatusForbidden)
		return
	}
	tunnel, reason := s.route(r.RemoteAddr, host)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	up, err := s.dial(ctx, "tcp", target, tunnel)
	cancel()
	if err != nil {
		s.logLimited("connect-error|"+target+"|"+reason+"|"+err.Error(), 5*time.Second, "hostname proxy connect %s route=%v (%s): %v", target, tunnel, reason, err)
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}
	s.logLimited("connect-ok|"+host+"|"+reason, 30*time.Second, "hostname proxy %s client=%s route=%s (%s)", host, r.RemoteAddr, map[bool]string{true: "WireGuard", false: "DIRECT"}[tunnel], reason)
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\nProxy-Agent: SplitWire\r\n\r\n"); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		client.Close()
		up.Close()
		return
	}
	go bridge(client, up)
}

func bridge(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if x, ok := a.(*net.TCPConn); ok {
			_ = x.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if x, ok := b.(*net.TCPConn); ok {
			_ = x.CloseWrite()
		}
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		host = strings.Split(r.Host, ":")[0]
	}
	if !s.matchesHost(host) {
		http.Error(w, "SplitWire proxy only accepts configured domains", http.StatusForbidden)
		return
	}
	tunnel, reason := s.route(r.RemoteAddr, host)
	u := *r.URL
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Host == "" {
		u.Host = r.Host
	}
	out := r.Clone(r.Context())
	out.URL = &u
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	out.Header.Del("Proxy-Connection")
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return s.dial(ctx, network, address, tunnel)
	}}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(out)
	if err != nil {
		s.logLimited("http-error|"+host+"|"+reason+"|"+err.Error(), 5*time.Second, "hostname HTTP proxy %s route=%v (%s): %v", host, tunnel, reason, err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) log(f string, a ...any) {
	if s.logf != nil {
		s.logf(f, a...)
	}
}

// logLimited keeps retry storms from turning splitwire.log into megabytes of
// identical lines. When the interval expires, the next emitted line reports
// how many identical messages were suppressed.
func (s *Server) logLimited(key string, interval time.Duration, f string, a ...any) {
	if s.logf == nil {
		return
	}
	now := time.Now()
	s.logMu.Lock()
	st := s.logState[key]
	if !st.last.IsZero() && now.Sub(st.last) < interval {
		st.suppressed++
		s.logState[key] = st
		s.logMu.Unlock()
		return
	}
	suppressed := st.suppressed
	st.last = now
	st.suppressed = 0
	s.logState[key] = st
	s.logMu.Unlock()
	if suppressed > 0 {
		f += " (suppressed %d identical messages)"
		a = append(a, suppressed)
	}
	s.logf(f, a...)
}

func ProbePAC(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	c, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(b), err
}
