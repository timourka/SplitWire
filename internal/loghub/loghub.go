package loghub

import (
	"errors"
	"io"
	"sync"
)

// Hub fan-outs every Write to all configured sinks. Writers are invoked with
// the same byte slice in registration order; one broken sink does not prevent
// the other sinks from receiving the record.
type Hub struct {
	mu      sync.RWMutex
	writers []io.Writer
}

func New(writers ...io.Writer) *Hub {
	h := &Hub{}
	for _, w := range writers {
		if w != nil {
			h.writers = append(h.writers, w)
		}
	}
	return h
}

func (h *Hub) Add(w io.Writer) {
	if w == nil {
		return
	}
	h.mu.Lock()
	h.writers = append(h.writers, w)
	h.mu.Unlock()
}

func (h *Hub) Write(p []byte) (int, error) {
	h.mu.RLock()
	ws := append([]io.Writer(nil), h.writers...)
	h.mu.RUnlock()
	if len(ws) == 0 {
		return len(p), nil
	}
	var errs []error
	for _, w := range ws {
		n, err := w.Write(p)
		if err != nil {
			errs = append(errs, err)
		} else if n != len(p) {
			errs = append(errs, io.ErrShortWrite)
		}
	}
	return len(p), errors.Join(errs...)
}

// Drain is the next UI update. Replace is true when the consumer must replace
// its whole visible buffer (startup, explicit clear, or consumer lag that made
// an incremental delta unsafe). Otherwise Text is only the newly written data.
type Drain struct {
	Text    string
	Replace bool
}

// Ring is a bounded in-memory log sink used by the GUI. It keeps a bounded
// history plus a separate pending delta. Logging goroutines never touch Win32
// controls and never wait for UI painting: notify is only a coalesced wake-up.
type Ring struct {
	mu       sync.Mutex
	buf      []byte
	pending  []byte
	maxBytes int
	notify   func()
	notified bool
	resync   bool
}

func NewRing(maxBytes int) *Ring {
	if maxBytes < 4096 {
		maxBytes = 4096
	}
	return &Ring{maxBytes: maxBytes}
}

// Seed initializes history read once from disk at application startup. The
// first UI drain is a full replace; subsequent writes are incremental deltas.
func (r *Ring) Seed(p []byte) {
	r.mu.Lock()
	r.appendHistoryLocked(p)
	r.pending = nil
	r.resync = true
	r.mu.Unlock()
}

func (r *Ring) SetNotify(fn func()) {
	r.mu.Lock()
	r.notify = fn
	should := fn != nil && (r.resync || len(r.pending) != 0) && !r.notified
	if should {
		r.notified = true
	}
	r.mu.Unlock()
	if should {
		fn()
	}
}

func (r *Ring) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	r.mu.Lock()
	r.appendHistoryLocked(cp)
	if !r.resync {
		if len(cp) >= r.maxBytes || len(r.pending)+len(cp) > r.maxBytes {
			// The UI fell behind far enough that blindly appending a truncated
			// delta could duplicate/lose text. Ask it to replace from history.
			r.pending = nil
			r.resync = true
		} else {
			r.pending = append(r.pending, cp...)
		}
	}
	fn := r.notify
	should := fn != nil && !r.notified
	if should {
		r.notified = true
	}
	r.mu.Unlock()
	if should {
		fn()
	}
	return len(p), nil
}

func (r *Ring) appendHistoryLocked(p []byte) {
	if len(p) >= r.maxBytes {
		r.buf = append(r.buf[:0], p[len(p)-r.maxBytes:]...)
		return
	}
	need := len(r.buf) + len(p) - r.maxBytes
	if need > 0 {
		copy(r.buf, r.buf[need:])
		r.buf = r.buf[:len(r.buf)-need]
	}
	r.buf = append(r.buf, p...)
}

func (r *Ring) Snapshot() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(append([]byte(nil), r.buf...))
}

// DrainAndAck returns either the pending delta or a full bounded snapshot and
// rearms notifications. A Write after the unlock posts another wake-up.
func (r *Ring) DrainAndAck() Drain {
	r.mu.Lock()
	var d Drain
	if r.resync {
		d = Drain{Text: string(append([]byte(nil), r.buf...)), Replace: true}
	} else {
		d = Drain{Text: string(append([]byte(nil), r.pending...))}
	}
	r.pending = r.pending[:0]
	r.resync = false
	r.notified = false
	r.mu.Unlock()
	return d
}

// SnapshotAndAck is retained for tests/compatibility. New UI code should use
// DrainAndAck so normal updates append only the delta.
func (r *Ring) SnapshotAndAck() string {
	return r.DrainAndAck().Text
}

func (r *Ring) Clear() {
	r.mu.Lock()
	r.buf = r.buf[:0]
	r.pending = r.pending[:0]
	r.resync = false
	r.notified = false
	r.mu.Unlock()
}
