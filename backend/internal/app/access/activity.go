package access

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ActivityTracker implements access.ActivitySink over the session repository.
//
// Touch is called for every proxied asset and every keystroke, so it cannot go
// to the database each time — a single page load of a management UI is dozens of
// requests, and a typing operator produces one call per character. It therefore
// writes at most once per interval per session, and does so off the caller's
// goroutine: nothing an operator does should wait on a bookkeeping UPDATE.
//
// The lost precision is irrelevant by construction: the reaper only compares the
// stamp against a timeout measured in minutes.
type ActivityTracker struct {
	sessions access.SessionRepository
	clock    iam.Clock
	interval time.Duration

	mu   sync.Mutex
	last map[uuid.UUID]time.Time
}

// NewActivityTracker builds a tracker that persists at most one stamp per
// session per interval.
func NewActivityTracker(sessions access.SessionRepository, clock iam.Clock, interval time.Duration) *ActivityTracker {
	if clock == nil {
		clock = iam.SystemClock{}
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ActivityTracker{
		sessions: sessions, clock: clock, interval: interval,
		last: map[uuid.UUID]time.Time{},
	}
}

// Touch records that a session is in use. Non-blocking.
func (t *ActivityTracker) Touch(sessionID uuid.UUID) {
	now := t.clock.Now()

	t.mu.Lock()
	if prev, ok := t.last[sessionID]; ok && now.Sub(prev) < t.interval {
		t.mu.Unlock()
		return
	}
	t.last[sessionID] = now
	t.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Best-effort: a dropped stamp costs at most one interval of precision,
		// and failing an operator's keystroke over it would be worse.
		_ = t.sessions.TouchActivity(ctx, sessionID, now)
	}()
}

// forget drops a session's throttle state. Called when a session ends so the map
// does not grow for the life of the process.
func (t *ActivityTracker) forget(sessionID uuid.UUID) {
	t.mu.Lock()
	delete(t.last, sessionID)
	t.mu.Unlock()
}
