package nat

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"splitwire/internal/packet"
)

type Meta struct{ IfIdx, SubIfIdx uint32 }
type outboundKey struct {
	Proto                 uint8
	Local, Remote         netip.Addr
	LocalPort, RemotePort uint16
}
type replyKey struct {
	Proto                  uint8
	Remote, Tunnel         netip.Addr
	RemotePort, TunnelPort uint16
}
type mapping struct {
	OriginalLocal netip.Addr
	OriginalPort  uint16
	TunnelPort    uint16
	Meta          Meta
	Seen          time.Time
}
type Mapper struct {
	mu      sync.Mutex
	v4, v6  netip.Addr
	byOut   map[outboundKey]*mapping
	byReply map[replyKey]*mapping
	next    uint16
}

func New(v4, v6 netip.Addr) *Mapper {
	return &Mapper{v4: v4, v6: v6, byOut: map[outboundKey]*mapping{}, byReply: map[replyKey]*mapping{}, next: 40000}
}

func (m *Mapper) PrepareOutbound(raw []byte, meta Meta) (Meta, error) {
	p, err := packet.Parse(raw)
	if err != nil {
		return meta, err
	}
	if p.Protocol != packet.ProtoTCP && p.Protocol != packet.ProtoUDP {
		return meta, fmt.Errorf("unsupported protocol %d", p.Protocol)
	}
	tun := m.v6
	if p.Src.Is4() {
		tun = m.v4
	}
	if !tun.IsValid() {
		return meta, fmt.Errorf("no tunnel address for %s", p.Src)
	}
	okey := outboundKey{p.Protocol, p.Src, p.Dst, p.SrcPort, p.DstPort}
	m.mu.Lock()
	mp, ok := m.byOut[okey]
	if !ok {
		tp := p.SrcPort
		rkey := replyKey{p.Protocol, p.Dst, tun, p.DstPort, tp}
		if _, exists := m.byReply[rkey]; exists {
			found := false
			for n := 0; n < 21000; n++ {
				tp = m.next
				m.next++
				if m.next > 60999 {
					m.next = 40000
				}
				rkey.TunnelPort = tp
				if _, exists = m.byReply[rkey]; !exists {
					found = true
					break
				}
			}
			if !found {
				m.mu.Unlock()
				return meta, fmt.Errorf("no free tunnel-side source port")
			}
		}
		mp = &mapping{OriginalLocal: p.Src, OriginalPort: p.SrcPort, TunnelPort: tp, Meta: meta, Seen: time.Now()}
		m.byOut[okey] = mp
		m.byReply[rkey] = mp
	} else {
		mp.Seen = time.Now()
		mp.Meta = meta
	}
	m.mu.Unlock()
	if err := packet.RewriteSrc(raw, tun); err != nil {
		return meta, err
	}
	if mp.TunnelPort != p.SrcPort {
		if err := packet.RewriteSrcPort(raw, mp.TunnelPort); err != nil {
			return meta, err
		}
	}
	return meta, nil
}

func (m *Mapper) RestoreInbound(raw []byte) (Meta, bool, error) {
	p, err := packet.Parse(raw)
	if err != nil {
		return Meta{}, false, err
	}
	if p.Protocol != packet.ProtoTCP && p.Protocol != packet.ProtoUDP {
		return Meta{}, false, nil
	}
	key := replyKey{p.Protocol, p.Src, p.Dst, p.SrcPort, p.DstPort}
	m.mu.Lock()
	mp, ok := m.byReply[key]
	var originalLocal netip.Addr
	var originalPort uint16
	var meta Meta
	if ok {
		mp.Seen = time.Now()
		originalLocal, originalPort, meta = mp.OriginalLocal, mp.OriginalPort, mp.Meta
	}
	m.mu.Unlock()
	if !ok {
		return Meta{}, false, nil
	}
	if err := packet.RewriteDst(raw, originalLocal); err != nil {
		return Meta{}, false, err
	}
	if p.DstPort != originalPort {
		if err := packet.RewriteDstPort(raw, originalPort); err != nil {
			return Meta{}, false, err
		}
	}
	return meta, true, nil
}

func (m *Mapper) Sweep(age time.Duration) {
	cut := time.Now().Add(-age)
	m.mu.Lock()
	for k, mp := range m.byOut {
		if mp.Seen.Before(cut) {
			delete(m.byOut, k)
			tun := m.v6
			if k.Local.Is4() {
				tun = m.v4
			}
			delete(m.byReply, replyKey{k.Proto, k.Remote, tun, k.RemotePort, mp.TunnelPort})
		}
	}
	m.mu.Unlock()
}
