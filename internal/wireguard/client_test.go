package wireguard

import (
	"testing"
	"time"
)

func TestSessionUsableRekeysWithoutRejectingCurrentTraffic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &session{created: now.Add(-109 * time.Second)}
	if usable, rekey := sessionUsable(s, now); !usable || rekey {
		t.Fatalf("109s: usable=%v rekey=%v, want true/false", usable, rekey)
	}

	s.created = now.Add(-110 * time.Second)
	if usable, rekey := sessionUsable(s, now); !usable || !rekey {
		t.Fatalf("110s: usable=%v rekey=%v, want true/true", usable, rekey)
	}

	s.created = now.Add(-169 * time.Second)
	if usable, rekey := sessionUsable(s, now); !usable || !rekey {
		t.Fatalf("169s: usable=%v rekey=%v, want true/true", usable, rekey)
	}

	s.created = now.Add(-170 * time.Second)
	if usable, rekey := sessionUsable(s, now); usable || rekey {
		t.Fatalf("170s: usable=%v rekey=%v, want false/false", usable, rekey)
	}
}

func TestSessionUsableRejectsCounterLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &session{created: now}
	s.sendCounter.Store(1 << 60)
	if usable, rekey := sessionUsable(s, now); usable || rekey {
		t.Fatalf("counter limit: usable=%v rekey=%v, want false/false", usable, rekey)
	}
}
