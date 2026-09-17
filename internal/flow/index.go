package flow

import (
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Key struct {
	Proto                 uint8
	Local, Remote         netip.Addr
	LocalPort, RemotePort uint16
}

type localKey struct {
	Proto uint8
	Local netip.Addr // invalid means any local address
	Port  uint16
}

type Process struct {
	PID        uint32
	Name, Path string
}

type entry struct {
	p    Process
	seen time.Time
}

type socketEntry struct {
	key localKey
	entry
}

type Index struct {
	mu sync.RWMutex

	// Exact 5-tuples from live FLOW events.
	m map[Key]entry

	// snapshotExact/locals are lower-priority historical fallbacks for endpoints
	// that existed before WinDivert handles were opened.
	snapshotExact map[Key]entry

	// locals are snapshot-only fallbacks for endpoints that existed before the
	// SOCKET handle was opened (WinDivert cannot report historical SOCKET events).
	locals map[localKey]entry

	// Live SOCKET ownership is keyed by WinDivert EndpointId so a late CLOSE for
	// an old socket cannot delete a newly reused proto/address/port tuple.
	sockets     map[uint64]socketEntry
	socketLocal map[localKey]map[uint64]entry

	notify chan struct{}
}

func New() *Index {
	return &Index{
		m:             map[Key]entry{},
		snapshotExact: map[Key]entry{},
		locals:        map[localKey]entry{},
		sockets:       map[uint64]socketEntry{},
		socketLocal:   map[localKey]map[uint64]entry{},
		notify:        make(chan struct{}, 1),
	}
}

func NormalizeProcess(p Process) Process {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" && p.Path != "" {
		p.Name = filepath.Base(strings.ReplaceAll(p.Path, "\\", "/"))
	}
	return p
}

func normalizeLocal(a netip.Addr) netip.Addr {
	if !a.IsValid() || a.IsUnspecified() {
		return netip.Addr{}
	}
	return a.Unmap()
}

// Add records exact FLOW/IP-Helper ownership only. It deliberately does not
// create local-port ownership: doing so would let an expired UDP FLOW outlive
// the socket that created it.
func (i *Index) Add(k Key, p Process) {
	p = NormalizeProcess(p)
	i.mu.Lock()
	i.m[k] = entry{p: p, seen: time.Now()}
	i.mu.Unlock()
	i.signal()
}

// AddSnapshotExact records a pre-existing TCP connection discovered through
// IP Helper. Live FLOW/SOCKET ownership has priority over this fallback.
func (i *Index) AddSnapshotExact(k Key, p Process) {
	p = NormalizeProcess(p)
	i.mu.Lock()
	i.snapshotExact[k] = entry{p: p, seen: time.Now()}
	i.mu.Unlock()
	i.signal()
}

// AddLocal records a historical/snapshot fallback. Live SOCKET events should
// use AddSocket so CLOSE can remove the exact EndpointId instance safely.
func (i *Index) AddLocal(proto uint8, local netip.Addr, port uint16, p Process) {
	if port == 0 {
		return
	}
	p = NormalizeProcess(p)
	local = normalizeLocal(local)
	i.mu.Lock()
	i.locals[localKey{Proto: proto, Local: local, Port: port}] = entry{p: p, seen: time.Now()}
	i.mu.Unlock()
	i.signal()
}

// AddSocket records a live WinDivert SOCKET endpoint. A wildcard bind
// (0.0.0.0/::) is normalized to an invalid netip.Addr sentinel so packets sent
// through the concrete local interface address can still match it.
func (i *Index) AddSocket(endpointID uint64, proto uint8, local netip.Addr, port uint16, p Process) {
	if endpointID == 0 || port == 0 {
		// EndpointId should be present on WinDivert 2.x. Keep a safe compatibility
		// fallback rather than losing attribution entirely on an unusual build.
		i.AddLocal(proto, local, port, p)
		return
	}
	p = NormalizeProcess(p)
	lk := localKey{Proto: proto, Local: normalizeLocal(local), Port: port}
	now := time.Now()

	i.mu.Lock()
	if old, ok := i.sockets[endpointID]; ok {
		i.deleteSocketIndexLocked(endpointID, old.key)
	}
	e := entry{p: p, seen: now}
	i.sockets[endpointID] = socketEntry{key: lk, entry: e}
	bucket := i.socketLocal[lk]
	if bucket == nil {
		bucket = make(map[uint64]entry)
		i.socketLocal[lk] = bucket
	}
	bucket[endpointID] = e
	i.mu.Unlock()
	i.signal()
}

func (i *Index) Delete(k Key) {
	i.mu.Lock()
	delete(i.m, k)
	i.mu.Unlock()
}

// DeleteLocal removes only snapshot fallback ownership. It is retained for
// snapshot maintenance/tests; live SOCKET_CLOSE should call DeleteSocket.
func (i *Index) DeleteLocal(proto uint8, local netip.Addr, port uint16) {
	local = normalizeLocal(local)
	i.mu.Lock()
	delete(i.locals, localKey{Proto: proto, Local: local, Port: port})
	if local.IsValid() {
		delete(i.locals, localKey{Proto: proto, Local: netip.Addr{}, Port: port})
	}
	i.mu.Unlock()
}

func (i *Index) deleteSocketIndexLocked(endpointID uint64, lk localKey) {
	delete(i.sockets, endpointID)
	if bucket := i.socketLocal[lk]; bucket != nil {
		delete(bucket, endpointID)
		if len(bucket) == 0 {
			delete(i.socketLocal, lk)
		}
	}
}

func (i *Index) DeleteSocket(endpointID uint64) {
	if endpointID == 0 {
		return
	}
	i.mu.Lock()
	if old, ok := i.sockets[endpointID]; ok {
		i.deleteSocketIndexLocked(endpointID, old.key)
	}
	i.mu.Unlock()
}

func (i *Index) signal() {
	select {
	case i.notify <- struct{}{}:
	default:
	}
}

func newest(bucket map[uint64]entry) (entry, bool) {
	var best entry
	ok := false
	for _, e := range bucket {
		if !ok || e.seen.After(best.seen) {
			best, ok = e, true
		}
	}
	return best, ok
}

func (i *Index) Lookup(k Key) (Process, bool) {
	exactLocal := localKey{Proto: k.Proto, Local: normalizeLocal(k.Local), Port: k.LocalPort}
	wildLocal := localKey{Proto: k.Proto, Local: netip.Addr{}, Port: k.LocalPort}

	i.mu.RLock()
	e, ok := i.m[k]
	if !ok {
		e, ok = newest(i.socketLocal[exactLocal])
	}
	if !ok && exactLocal.Local.IsValid() {
		e, ok = newest(i.socketLocal[wildLocal])
	}
	if !ok {
		e, ok = i.snapshotExact[k]
	}
	if !ok {
		e, ok = i.locals[exactLocal]
	}
	if !ok && exactLocal.Local.IsValid() {
		e, ok = i.locals[wildLocal]
	}
	i.mu.RUnlock()
	return e.p, ok
}

func (i *Index) WaitLookup(k Key, d time.Duration) (Process, bool) {
	if p, ok := i.Lookup(k); ok {
		return p, true
	}
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		select {
		case <-i.notify:
			if p, ok := i.Lookup(k); ok {
				return p, true
			}
		case <-deadline.C:
			return Process{}, false
		}
	}
}

func (i *Index) Sweep(age time.Duration) {
	cut := time.Now().Add(-age)
	i.mu.Lock()
	for k, e := range i.m {
		if e.seen.Before(cut) {
			delete(i.m, k)
		}
	}
	for k, e := range i.snapshotExact {
		if e.seen.Before(cut) {
			delete(i.snapshotExact, k)
		}
	}
	for k, e := range i.locals {
		if e.seen.Before(cut) {
			delete(i.locals, k)
		}
	}
	// Live SOCKET entries are not age-swept: their authoritative lifetime is
	// EndpointId -> SOCKET_CLOSE, and long-lived UDP sockets are normal.
	i.mu.Unlock()
}

func Match(p Process, names []string) bool {
	name := strings.ToLower(p.Name)
	path := strings.ToLower(strings.ReplaceAll(p.Path, "/", "\\"))
	for _, x := range names {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" {
			continue
		}
		if strings.Contains(x, "\\") {
			if path == strings.ReplaceAll(x, "/", "\\") {
				return true
			}
		} else if name == strings.ToLower(filepath.Base(strings.ReplaceAll(x, "\\", "/"))) {
			return true
		}
	}
	return false
}
