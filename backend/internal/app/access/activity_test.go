package access

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The throttle exists so a typing operator does not generate one UPDATE per
// keystroke. It must not swallow the FIRST touch, which is the one that proves
// the session is alive at all.
func TestActivityTrackerWritesFirstTouchImmediately(t *testing.T) {
	sessions := newFakeSessions()
	clk := &fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	tr := NewActivityTracker(sessions, clk, 30*time.Second)

	id := uuid.New()
	tr.Touch(id)
	waitFor(t, func() bool { return len(sessions.touchedIDs()) == 1 })
}

// Within the interval, further touches must not reach the database.
func TestActivityTrackerThrottlesWithinInterval(t *testing.T) {
	sessions := newFakeSessions()
	clk := &fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	tr := NewActivityTracker(sessions, clk, 30*time.Second)

	id := uuid.New()
	tr.Touch(id)
	waitFor(t, func() bool { return len(sessions.touchedIDs()) == 1 })

	for i := 0; i < 50; i++ {
		clk.t = clk.t.Add(100 * time.Millisecond) // still inside the interval
		tr.Touch(id)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(sessions.touchedIDs()); n != 1 {
		t.Errorf("throttle leaked: %d writes for 51 touches inside one interval", n)
	}
}

// Past the interval it must write again — otherwise a session busy for hours
// would keep the stamp from its first second and get reaped mid-use.
func TestActivityTrackerWritesAgainAfterInterval(t *testing.T) {
	sessions := newFakeSessions()
	clk := &fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	tr := NewActivityTracker(sessions, clk, 30*time.Second)

	id := uuid.New()
	tr.Touch(id)
	waitFor(t, func() bool { return len(sessions.touchedIDs()) == 1 })

	clk.t = clk.t.Add(31 * time.Second)
	tr.Touch(id)
	waitFor(t, func() bool { return len(sessions.touchedIDs()) == 2 })
}

// Sessions must be throttled independently; one busy session must not suppress
// another's first stamp.
func TestActivityTrackerThrottlesPerSession(t *testing.T) {
	sessions := newFakeSessions()
	clk := &fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	tr := NewActivityTracker(sessions, clk, 30*time.Second)

	a, b := uuid.New(), uuid.New()
	tr.Touch(a)
	tr.Touch(b)
	waitFor(t, func() bool { return len(sessions.touchedIDs()) == 2 })
}

// forget drops throttle state so the map does not grow for the process lifetime.
func TestActivityTrackerForgetsEndedSessions(t *testing.T) {
	sessions := newFakeSessions()
	clk := &fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	tr := NewActivityTracker(sessions, clk, 30*time.Second)

	id := uuid.New()
	tr.Touch(id)
	tr.forget(id)

	tr.mu.Lock()
	_, present := tr.last[id]
	tr.mu.Unlock()
	if present {
		t.Error("throttle state retained after forget")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
