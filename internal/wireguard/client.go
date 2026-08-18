package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"splitwire/internal/cryptox"
	"splitwire/internal/packet"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	msgInit      = 1
	msgResp      = 2
	msgCookie    = 3
	msgTransport = 4
	initSize     = 148
	respSize     = 92
	cookieSize   = 64
)

var zeroNonce = [12]byte{}

type Params struct {
	PrivateKey, PeerPublicKey, PresharedKey [32]byte
	Endpoint                                string
	InterfaceIndex                          uint32
	MTU                                     int
	Keepalive                               int
	Logf                                    func(string, ...any)
}
type responseMsg struct{ raw []byte }
type Client struct {
	p                  Params
	conn               *net.UDPConn
	endpoint           *net.UDPAddr
	localPort          int
	priv               *ecdh.PrivateKey
	pub                [32]byte
	peerPub            [32]byte
	psk                [32]byte
	mac1Key, cookieKey [32]byte
	cookieMu           sync.Mutex
	cookie             [16]byte
	cookieAt           time.Time
	hsMu               sync.Mutex
	ioMu               sync.Mutex
	workerWG           sync.WaitGroup
	respCh             chan []byte
	cookieCh           chan []byte
	sessMu             sync.RWMutex
	sessions           map[uint32]*session
	current            *session
	plain              chan []byte
	done               chan struct{}
	closeOnce          sync.Once
	txBytes, rxBytes   atomic.Uint64
	lastHandshake      atomic.Int64
}
type session struct {
	localIndex, remoteIndex uint32
	send, recv              cryptox.AEAD
	sendCounter             atomic.Uint64
	replay                  replay
	created                 time.Time
}
type replay struct {
	mu   sync.Mutex
	max  uint64
	init bool
	seen [32]uint64
}

func (r *replay) Accept(n uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	const win = 2048
	if !r.init {
		r.init = true
		r.max = n
		r.seen[n%win/64] |= 1 << (n % 64)
		return true
	}
	if n+win <= r.max {
		return false
	}
	if n > r.max {
		delta := n - r.max
		if delta >= win {
			for i := range r.seen {
				r.seen[i] = 0
			}
		} else {
			for x := r.max + 1; x <= n; x++ {
				idx := x % win
				r.seen[idx/64] &^= 1 << (idx % 64)
			}
		}
		r.max = n
	}
	idx := n % win
	mask := uint64(1) << (idx % 64)
	if r.seen[idx/64]&mask != 0 {
		return false
	}
	r.seen[idx/64] |= mask
	return true
}

func New(p Params) (*Client, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(p.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	pubb := priv.PublicKey().Bytes()
	var pub [32]byte
	copy(pub[:], pubb)
	ep, err := resolveEndpoint(p.Endpoint)
	if err != nil {
		return nil, err
	}
	network := "udp4"
	listen := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if ep.IP.To4() == nil {
		network = "udp6"
		listen = &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}
	}
	conn, err := net.ListenUDP(network, listen)
	if err != nil {
		return nil, err
	}
	if p.InterfaceIndex != 0 {
		if err := bindUDPToInterface(conn, p.InterfaceIndex, ep.IP.To4() == nil); err != nil {
			conn.Close()
			return nil, fmt.Errorf("bind WireGuard UDP to physical interface %d: %w", p.InterfaceIndex, err)
		}
	}
	c := &Client{p: p, conn: conn, endpoint: ep, localPort: conn.LocalAddr().(*net.UDPAddr).Port, priv: priv, pub: pub, peerPub: p.PeerPublicKey, psk: p.PresharedKey, respCh: make(chan []byte, 8), cookieCh: make(chan []byte, 8), sessions: map[uint32]*session{}, plain: make(chan []byte, 4096), done: make(chan struct{})}
	b := append([]byte("mac1----"), c.peerPub[:]...)
	c.mac1Key = cryptox.Blake2s256(b)
	b = append([]byte("cookie--"), c.peerPub[:]...)
	c.cookieKey = cryptox.Blake2s256(b)
	c.workerWG.Add(2)
	go func() { defer c.workerWG.Done(); c.reader() }()
	go func() { defer c.workerWG.Done(); c.reaper() }()
	if p.Keepalive > 0 {
		c.workerWG.Add(1)
		go func() { defer c.workerWG.Done(); c.keepalive() }()
	}
	return c, nil
}
func resolveEndpoint(s string) (*net.UDPAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty endpoint")
	}
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint %q: %w", s, err)
	}
	return a, nil
}
func (c *Client) LocalPort() int { return c.localPort }
func (c *Client) EndpointIP() netip.Addr {
	a, _ := netip.AddrFromSlice(c.endpoint.IP)
	return a.Unmap()
}
func (c *Client) Packets() <-chan []byte { return c.plain }
func (c *Client) LastHandshake() time.Time {
	n := c.lastHandshake.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
func (c *Client) Stats() (uint64, uint64) { return c.txBytes.Load(), c.rxBytes.Load() }
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.Close()
		c.workerWG.Wait()
		c.ioMu.Lock()
		defer c.ioMu.Unlock()
		c.sessMu.Lock()
		for _, s := range c.sessions {
			s.send.Close()
			s.recv.Close()
		}
		c.sessions = map[uint32]*session{}
		c.current = nil
		c.sessMu.Unlock()
	})
	return nil
}
func (c *Client) log(f string, a ...any) {
	if c.p.Logf != nil {
		c.p.Logf(f, a...)
	}
}

func (c *Client) SendPacket(ctx context.Context, raw []byte) error {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	s, err := c.ensureSession(ctx)
	if err != nil {
		return err
	}
	padded := packet.Pad16(raw)
	counter := s.sendCounter.Add(1) - 1
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	sealed, err := s.send.Seal(nonce, padded, nil)
	if err != nil {
		return err
	}
	out := make([]byte, 16+len(sealed))
	binary.LittleEndian.PutUint32(out[0:4], msgTransport)
	binary.LittleEndian.PutUint32(out[4:8], s.remoteIndex)
	binary.LittleEndian.PutUint64(out[8:16], counter)
	copy(out[16:], sealed)
	n, err := c.conn.WriteToUDP(out, c.endpoint)
	if err == nil {
		c.txBytes.Add(uint64(n))
	}
	return err
}
func (c *Client) ensureSession(ctx context.Context) (*session, error) {
	c.sessMu.RLock()
	s := c.current
	c.sessMu.RUnlock()
	if s != nil && time.Since(s.created) < 110*time.Second && s.sendCounter.Load() < (1<<60) {
		return s, nil
	}
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	c.sessMu.RLock()
	s = c.current
	c.sessMu.RUnlock()
	if s != nil && time.Since(s.created) < 110*time.Second {
		return s, nil
	}
	return c.handshake(ctx)
}

type initState struct {
	sender      uint32
	epriv       *ecdh.PrivateKey
	chain, hash [32]byte
	mac1        [16]byte
}

func (c *Client) handshake(ctx context.Context) (*session, error) {
	for attempt := 0; attempt < 5; attempt++ {
		st, msg, err := c.makeInitiation()
		if err != nil {
			return nil, err
		}
		if _, err = c.conn.WriteToUDP(msg, c.endpoint); err != nil {
			return nil, err
		}
		c.log("WireGuard handshake attempt %d", attempt+1)
		timer := time.NewTimer(time.Second)
	wait:
		for {
			select {
			case raw := <-c.respCh:
				if len(raw) == respSize && binary.LittleEndian.Uint32(raw[8:12]) == st.sender {
					s, err := c.consumeResponse(st, raw)
					if err == nil {
						timer.Stop()
						c.installSession(s)
						c.lastHandshake.Store(time.Now().UnixNano())
						c.log("WireGuard handshake OK")
						return s, nil
					}
				}
			case raw := <-c.cookieCh:
				if len(raw) == cookieSize && binary.LittleEndian.Uint32(raw[4:8]) == st.sender {
					if c.consumeCookie(st, raw) == nil {
						timer.Stop()
						break wait
					}
				}
			case <-timer.C:
				break wait
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-c.done:
				timer.Stop()
				return nil, net.ErrClosed
			}
		}
	}
	return nil, errors.New("WireGuard handshake timed out")
}
func (c *Client) makeInitiation() (initState, []byte, error) {
	curve := ecdh.X25519()
	eraw := make([]byte, 32)
	if _, err := rand.Read(eraw); err != nil {
		return initState{}, nil, err
	}
	epriv, err := curve.NewPrivateKey(eraw)
	if err != nil {
		return initState{}, nil, err
	}
	epub := epriv.PublicKey().Bytes()
	chain := cryptox.Blake2s256([]byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"))
	hash := mixHash(chain, []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"))
	hash = mixHash(hash, c.peerPub[:])
	chain = cryptox.KDF1(chain[:], epub)
	hash = mixHash(hash, epub)
	peerKey, err := curve.NewPublicKey(c.peerPub[:])
	if err != nil {
		return initState{}, nil, err
	}
	es, err := epriv.ECDH(peerKey)
	if err != nil {
		return initState{}, nil, err
	}
	var key [32]byte
	chain, key = cryptox.KDF2(chain[:], es)
	aead, err := cryptox.NewChaCha20Poly1305(key)
	if err != nil {
		return initState{}, nil, err
	}
	encStatic, err := aead.Seal(zeroNonce[:], c.pub[:], hash[:])
	aead.Close()
	if err != nil {
		return initState{}, nil, err
	}
	hash = mixHash(hash, encStatic)
	ss, err := c.priv.ECDH(peerKey)
	if err != nil {
		return initState{}, nil, err
	}
	chain, key = cryptox.KDF2(chain[:], ss)
	aead, err = cryptox.NewChaCha20Poly1305(key)
	if err != nil {
		return initState{}, nil, err
	}
	ts := tai64n()
	encTS, err := aead.Seal(zeroNonce[:], ts[:], hash[:])
	aead.Close()
	if err != nil {
		return initState{}, nil, err
	}
	hash = mixHash(hash, encTS)
	var idxb [4]byte
	if _, err := rand.Read(idxb[:]); err != nil {
		return initState{}, nil, err
	}
	sender := binary.LittleEndian.Uint32(idxb[:])
	if sender == 0 {
		sender = 1
	}
	msg := make([]byte, initSize)
	binary.LittleEndian.PutUint32(msg[0:4], msgInit)
	binary.LittleEndian.PutUint32(msg[4:8], sender)
	copy(msg[8:40], epub)
	copy(msg[40:88], encStatic)
	copy(msg[88:116], encTS)
	mac1 := cryptox.Blake2s128Keyed(c.mac1Key[:], msg[:116])
	copy(msg[116:132], mac1[:])
	c.cookieMu.Lock()
	if time.Since(c.cookieAt) < 2*time.Minute {
		mac2 := cryptox.Blake2s128Keyed(c.cookie[:], msg[:132])
		copy(msg[132:148], mac2[:])
	}
	c.cookieMu.Unlock()
	return initState{sender, epriv, chain, hash, mac1}, msg, nil
}
func (c *Client) consumeResponse(st initState, msg []byte) (*session, error) {
	// Verify responder MAC1 keyed by our static public key.
	k := cryptox.Blake2s256(append([]byte("mac1----"), c.pub[:]...))
	want := cryptox.Blake2s128Keyed(k[:], msg[:60])
	if subtle.ConstantTimeCompare(want[:], msg[60:76]) != 1 {
		return nil, errors.New("bad response MAC1")
	}
	remoteIndex := binary.LittleEndian.Uint32(msg[4:8])
	rep := msg[12:44]
	chain := cryptox.KDF1(st.chain[:], rep)
	hash := mixHash(st.hash, rep)
	curve := ecdh.X25519()
	repPub, err := curve.NewPublicKey(rep)
	if err != nil {
		return nil, err
	}
	ee, err := st.epriv.ECDH(repPub)
	if err != nil {
		return nil, err
	}
	chain = cryptox.KDF1(chain[:], ee)
	se, err := c.priv.ECDH(repPub)
	if err != nil {
		return nil, err
	}
	chain = cryptox.KDF1(chain[:], se)
	var tau, key [32]byte
	chain, tau, key = cryptox.KDF3(chain[:], c.psk[:])
	hash = mixHash(hash, tau[:])
	aead, err := cryptox.NewChaCha20Poly1305(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(zeroNonce[:], msg[44:60], hash[:])
	aead.Close()
	if err != nil || len(plain) != 0 {
		return nil, errors.New("bad response authenticator")
	}
	sendKey, recvKey := cryptox.KDF2(chain[:], nil)
	send, err := cryptox.NewChaCha20Poly1305(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := cryptox.NewChaCha20Poly1305(recvKey)
	if err != nil {
		send.Close()
		return nil, err
	}
	return &session{localIndex: st.sender, remoteIndex: remoteIndex, send: send, recv: recv, created: time.Now()}, nil
}
func (c *Client) consumeCookie(st initState, msg []byte) error {
	var nonce [24]byte
	copy(nonce[:], msg[8:32])
	x, _ := cryptox.NewXChaCha(c.cookieKey)
	plain, err := x.Open(nonce[:], msg[32:64], st.mac1[:])
	if err != nil || len(plain) != 16 {
		return errors.New("bad cookie reply")
	}
	c.cookieMu.Lock()
	copy(c.cookie[:], plain)
	c.cookieAt = time.Now()
	c.cookieMu.Unlock()
	return nil
}
func (c *Client) installSession(s *session) {
	c.sessMu.Lock()
	c.sessions[s.localIndex] = s
	c.current = s
	c.sessMu.Unlock()
}
func (c *Client) reader() {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !sameEndpoint(from, c.endpoint) {
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		if n < 4 {
			continue
		}
		switch binary.LittleEndian.Uint32(raw[:4]) {
		case msgResp:
			select {
			case c.respCh <- raw:
			default:
			}
		case msgCookie:
			select {
			case c.cookieCh <- raw:
			default:
			}
		case msgTransport:
			c.handleTransport(raw)
		}
	}
}
func sameEndpoint(a, b *net.UDPAddr) bool { return a.Port == b.Port && a.IP.Equal(b.IP) }
func (c *Client) handleTransport(raw []byte) {
	if len(raw) < 32 {
		return
	}
	idx := binary.LittleEndian.Uint32(raw[4:8])
	counter := binary.LittleEndian.Uint64(raw[8:16])
	c.sessMu.RLock()
	s := c.sessions[idx]
	c.sessMu.RUnlock()
	if s == nil || !s.replay.Accept(counter) {
		return
	}
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := s.recv.Open(nonce, raw[16:], nil)
	if err != nil {
		return
	}
	plain = packet.TrimToIPLength(plain)
	if len(plain) == 0 {
		return
	}
	c.rxBytes.Add(uint64(len(raw)))
	select {
	case c.plain <- plain:
	case <-c.done:
	}
}

func (c *Client) keepalive() {
	d := time.Duration(c.p.Keepalive) * time.Second
	if d <= 0 {
		return
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			if _, err := c.currentSession(); err == nil {
				_ = c.SendPacket(ctx, nil)
			}
			cancel()
		case <-c.done:
			return
		}
	}
}
func (c *Client) currentSession() (*session, error) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	if c.current == nil {
		return nil, errors.New("no session")
	}
	return c.current, nil
}
func (c *Client) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.sessMu.Lock()
			for idx, s := range c.sessions {
				if s != c.current && time.Since(s.created) > 3*time.Minute {
					s.send.Close()
					s.recv.Close()
					delete(c.sessions, idx)
				}
			}
			c.sessMu.Unlock()
		case <-c.done:
			return
		}
	}
}
func mixHash(h [32]byte, data []byte) [32]byte {
	b := make([]byte, 0, 32+len(data))
	b = append(b, h[:]...)
	b = append(b, data...)
	return cryptox.Blake2s256(b)
}
func tai64n() (out [12]byte) {
	now := time.Now()
	binary.BigEndian.PutUint64(out[:8], 0x400000000000000a+uint64(now.Unix()))
	nano := uint32(now.Nanosecond()) &^ uint32(0x1000000-1)
	binary.BigEndian.PutUint32(out[8:], nano)
	return
}
