package term

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

type fakeEvents struct {
	mu    sync.Mutex
	kinds []string
	gate  chan struct{} // when set, each write waits on it
}

func (f *fakeEvents) RecordEvent(_ context.Context, _ uuid.UUID, kind string, _ map[string]any) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kinds = append(f.kinds, kind)
	return nil
}

func (f *fakeEvents) ListEvents(context.Context, access.Scope, uuid.UUID, int) ([]access.Event, error) {
	return nil, nil
}

func (f *fakeEvents) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.kinds...)
}

func TestActivity_WritesInOrderAndDrainsOnClose(t *testing.T) {
	f := &fakeEvents{}
	a := NewActivity(f, uuid.New(), nil)
	for _, k := range []string{"a", "b", "c"} {
		a.Record(k, nil)
	}
	a.Close()
	if got := f.got(); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("got %v", got)
	}
	a.Record("after close", nil) // must not panic on the closed queue
	a.Close()
}

// A database that cannot keep up costs dropped timeline rows, never a stalled
// terminal.
func TestActivity_NeverBlocks(t *testing.T) {
	f := &fakeEvents{gate: make(chan struct{})}
	a := NewActivity(f, uuid.New(), nil)
	for i := 0; i < activityQueue+50; i++ {
		a.Record("x", nil)
	}
	if a.Dropped() == 0 {
		t.Error("nothing dropped on a full queue")
	}
	close(f.gate)
	a.Close()

	var nilA *Activity
	nilA.Record("x", nil)
	nilA.Close()
	if NewActivity(nil, uuid.New(), nil) != nil {
		t.Error("an activity with nowhere to write should be nil")
	}
}
