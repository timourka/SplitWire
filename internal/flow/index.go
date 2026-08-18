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
type Index struct {
	mu     sync.RWMutex
	m      map[Key]entry
	locals map[localKey]entry
	notify chan struct{}
}

func New() *Index {
	return &Index{m: map[Key]entry{}, locals: map[localKey]entry{}, notify: make(chan struct{}, 1)}
}
func NormalizeProcess(p Process) Process {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" && p.Path != "" {
		p.Name = filepath.Base(strings.ReplaceAll(p.Path, "\\", "/"))
	}
	return p
}
func (i *Index) Add(k Key, p Process) {
	p = NormalizeProcess(p)
	now := time.Now()
	i.mu.Lock()
	i.m[k] = entry{p, now}
	i.locals[localKey{k.Proto, k.Local.Unmap(), k.LocalPort}] = entry{p, now}
	i.mu.Unlock()
	i.signal()
}
func (i *Index) AddLocal(proto uint8, local netip.Addr, port uint16, p Process) {
	p = NormalizeProcess(p)
	if local.IsValid() {
		local = local.Unmap()
	}
	i.mu.Lock()
	i.locals[localKey{proto, local, port}] = entry{p, time.Now()}
	i.mu.Unlock()
	i.signal()
}
func (i *Index) Delete(k Key) {
	i.mu.Lock()
	delete(i.m, k)
	delete(i.locals, localKey{k.Proto, k.Local.Unmap(), k.LocalPort})
	i.mu.Unlock()
}
func (i *Index) signal() {
	select {
	case i.notify <- struct{}{}:
	default:
	}
}
func (i *Index) Lookup(k Key) (Process, bool) {
	i.mu.RLock()
	e, ok := i.m[k]
	if !ok {
		e, ok = i.locals[localKey{k.Proto, k.Local.Unmap(), k.LocalPort}]
	}
	if !ok {
		e, ok = i.locals[localKey{k.Proto, netip.Addr{}, k.LocalPort}]
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
	for k, e := range i.locals {
		if e.seen.Before(cut) {
			delete(i.locals, k)
		}
	}
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
