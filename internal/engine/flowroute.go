package engine

import (
	"sync"
	"time"

	"splitwire/internal/flow"
)

type flowRouteEntry struct {
	tunnel bool
	proc   flow.Process
	known  bool
	seen   time.Time
}

type flowRouteTable struct {
	mu sync.Mutex
	m  map[flow.Key]flowRouteEntry
}

func newFlowRouteTable() *flowRouteTable {
	return &flowRouteTable{m: make(map[flow.Key]flowRouteEntry)}
}

func (t *flowRouteTable) Lookup(k flow.Key) (flowRouteEntry, bool) {
	t.mu.Lock()
	e, ok := t.m[k]
	if ok {
		e.seen = time.Now()
		t.m[k] = e
	}
	t.mu.Unlock()
	return e, ok
}

func (t *flowRouteTable) Set(k flow.Key, tunnel bool, proc flow.Process, known bool) {
	t.mu.Lock()
	if _, exists := t.m[k]; !exists {
		t.m[k] = flowRouteEntry{tunnel: tunnel, proc: proc, known: known, seen: time.Now()}
	}
	t.mu.Unlock()
}
func (t *flowRouteTable) Delete(k flow.Key) { t.mu.Lock(); delete(t.m, k); t.mu.Unlock() }
func (t *flowRouteTable) Sweep(age time.Duration) {
	cut := time.Now().Add(-age)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.m {
		if e.seen.Before(cut) {
			delete(t.m, k)
		}
	}
}
