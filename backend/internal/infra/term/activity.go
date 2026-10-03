package term

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// Activity writes a terminal session's timeline events off the session's own
// path.
//
// Events are produced where the device's output is handled, and that must never
// wait on the database: a slow write would stall the operator's screen. So they
// go through a bounded queue to one writer, which drops rather than grows when
// the database cannot keep up — the timeline is an index into the recording,
// and the recording is the evidence of record.
//
// A nil *Activity is valid and discards everything.
type Activity struct {
	ch        chan activityEvent
	done      chan struct{}
	closeOnce sync.Once

	mu      sync.Mutex
	closed  bool
	dropped int
}

type activityEvent struct {
	kind string
	data map[string]any
}

const (
	// activityQueue absorbs a burst — a pasted block of configuration is a few
	// hundred lines at once — while bounding what a stalled database costs.
	activityQueue = 512
	// activityWriteTimeout bounds one write; a slow one is abandoned.
	activityWriteTimeout = 5 * time.Second
	// activityDrainGrace is how long Close waits for queued events, so the last
	// commands of a session are not lost to the teardown right after them.
	activityDrainGrace = 5 * time.Second
)

// NewActivity starts the writer for one session. It returns nil when there is
// nothing to write to.
func NewActivity(rec access.EventRecorder, sessionID uuid.UUID, log *zap.Logger) *Activity {
	if rec == nil {
		return nil
	}
	a := &Activity{ch: make(chan activityEvent, activityQueue), done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for ev := range a.ch {
			ctx, cancel := context.WithTimeout(context.Background(), activityWriteTimeout)
			err := rec.RecordEvent(ctx, sessionID, ev.kind, ev.data)
			cancel()
			if err != nil && log != nil {
				log.Debug("term: timeline event not recorded",
					zap.String("session_id", sessionID.String()),
					zap.String("kind", ev.kind), zap.Error(err))
			}
		}
	}()
	return a
}

// Record queues an event. It never blocks.
func (a *Activity) Record(kind string, data map[string]any) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	select {
	case a.ch <- activityEvent{kind: kind, data: data}:
	default:
		a.dropped++
	}
}

// Close stops the writer and waits, briefly, for what is queued.
func (a *Activity) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.ch)
		a.mu.Unlock()
	})
	select {
	case <-a.done:
	case <-time.After(activityDrainGrace):
	}
}

// Dropped reports how many events were discarded on a full queue. Test-facing.
func (a *Activity) Dropped() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}
