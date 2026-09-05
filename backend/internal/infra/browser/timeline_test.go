package browser

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// recEvents is an access.EventRecorder that keeps what it was told.
type recEvents struct {
	mu   sync.Mutex
	kind []string
	path []string
}

func (r *recEvents) RecordEvent(_ context.Context, _ uuid.UUID, kind string, data map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kind = append(r.kind, kind)
	p, _ := data["path"].(string)
	r.path = append(r.path, p)
	return nil
}

// ListEvents completes access.EventRecorder. The timeline only ever writes.
func (r *recEvents) ListEvents(context.Context, access.Scope, uuid.UUID, int) ([]access.Event, error) {
	return nil, nil
}

func (r *recEvents) all() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.kind...), append([]string(nil), r.path...)
}

func TestTimelineNilIsSilent(t *testing.T) {
	// The gateway serves sessions with no event recorder configured, and the call
	// sites must not have to know that.
	var tl *timeline
	tl.record("url_change", map[string]any{"path": "/"})
	tl.close()
	if w, d := tl.stats(); w != 0 || d != 0 {
		t.Fatalf("nil timeline counted something: written=%d dropped=%d", w, d)
	}
}

func TestTimelineCoalescesRepeats(t *testing.T) {
	// An admin dashboard that re-POSTs its status endpoint on a timer must not
	// bury the one request that mattered.
	rec := &recEvents{}
	tl := newTimeline(rec, uuid.New(), nil)
	for range 20 {
		tl.record("request", map[string]any{"method": "POST", "path": "/api/status"})
	}
	tl.record("request", map[string]any{"method": "POST", "path": "/api/firewall/policy"})
	tl.close()

	kinds, paths := rec.all()
	if len(kinds) != 2 {
		t.Fatalf("want 2 events, got %d: %v", len(kinds), paths)
	}
	if paths[0] != "/api/status" || paths[1] != "/api/firewall/policy" {
		t.Fatalf("unexpected timeline: %v", paths)
	}
}

func TestTimelineKeepsDistinctActions(t *testing.T) {
	// Coalescing is per action, not a global rate limit: a session that touches
	// twelve different screens has twelve things to show.
	rec := &recEvents{}
	tl := newTimeline(rec, uuid.New(), nil)
	for i := range 12 {
		tl.record("url_change", map[string]any{"method": "GET", "path": fmt.Sprintf("/page/%d", i)})
	}
	tl.close()

	if kinds, paths := rec.all(); len(kinds) != 12 {
		t.Fatalf("want 12 events, got %d: %v", len(kinds), paths)
	}
}

func TestTimelineSameMethodDifferentPathIsNotADuplicate(t *testing.T) {
	rec := &recEvents{}
	tl := newTimeline(rec, uuid.New(), nil)
	tl.record("request", map[string]any{"method": "POST", "path": "/a"})
	tl.record("request", map[string]any{"method": "DELETE", "path": "/a"})
	tl.record("request", map[string]any{"method": "POST", "path": "/b"})
	tl.close()

	if kinds, _ := rec.all(); len(kinds) != 3 {
		t.Fatalf("want 3 events, got %d", len(kinds))
	}
}

func TestTimelineCapsOneSession(t *testing.T) {
	// A page stuck in a redirect loop must not be able to write rows forever.
	rec := &recEvents{}
	tl := newTimeline(rec, uuid.New(), nil)
	for i := range tlMaxEvents + 500 {
		tl.record("url_change", map[string]any{"method": "GET", "path": fmt.Sprintf("/p/%d", i)})
	}
	tl.close()

	written, dropped := tl.stats()
	if written != tlMaxEvents {
		t.Fatalf("cap not enforced: wrote %d, cap is %d", written, tlMaxEvents)
	}
	if dropped == 0 {
		t.Fatal("nothing counted as dropped past the cap")
	}
}

func TestTimelineCloseIsIdempotent(t *testing.T) {
	// End can run twice (reaper and operator racing to close the same session);
	// the second must not panic on a closed channel.
	tl := newTimeline(&recEvents{}, uuid.New(), nil)
	tl.close()
	tl.close()
}

func TestStateChanging(t *testing.T) {
	for _, m := range []string{"POST", "put", "Patch", "DELETE"} {
		if !stateChanging(m) {
			t.Errorf("%q should count as a change", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", ""} {
		if stateChanging(m) {
			t.Errorf("%q should not count as a change", m)
		}
	}
}

func TestPageFurniture(t *testing.T) {
	// The point of the split: a stylesheet is never an action, an XHR can be.
	for _, rt := range []network.ResourceType{
		network.ResourceTypeImage, network.ResourceTypeStylesheet, network.ResourceTypeFont,
		network.ResourceTypeMedia, network.ResourceTypePing, network.ResourceTypePreflight,
	} {
		if !pageFurniture(rt) {
			t.Errorf("%s should be treated as page furniture", rt)
		}
	}
	for _, rt := range []network.ResourceType{
		network.ResourceTypeXHR, network.ResourceTypeFetch, network.ResourceTypeDocument,
	} {
		if pageFurniture(rt) {
			t.Errorf("%s should be able to reach the timeline", rt)
		}
	}
}

func TestPathOf(t *testing.T) {
	cases := map[string]string{
		"https://10.0.0.1/ng/firewall/policy": "/ng/firewall/policy",
		"https://10.0.0.1/api?vdom=root&q=1":  "/api?vdom=root&q=1",
		"https://10.0.0.1":                    "https://10.0.0.1",
		"about:blank":                         "about:blank",
	}
	for in, want := range cases {
		if got := pathOf(in); got != want {
			t.Errorf("pathOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// The timeline must never be able to stall the screencast callback: that
// callback is the frame pump, and a blocked pump is a frozen session.
func TestTimelineRecordNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	rec := &blockingEvents{gate: block}
	tl := newTimeline(rec, uuid.New(), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range tlQueue * 4 {
			tl.record("request", map[string]any{"method": "POST", "path": fmt.Sprintf("/x/%d", i)})
		}
	}()
	select {
	case <-done:
	case <-context.Background().Done():
	}
	close(block)
	tl.close()

	if _, dropped := tl.stats(); dropped == 0 {
		t.Fatal("a full queue should drop, and say so")
	}
}

// blockingEvents holds every write until its gate opens, standing in for a
// database that has stopped answering.
type blockingEvents struct{ gate chan struct{} }

func (b *blockingEvents) RecordEvent(_ context.Context, _ uuid.UUID, _ string, _ map[string]any) error {
	<-b.gate
	return nil
}

func (b *blockingEvents) ListEvents(context.Context, access.Scope, uuid.UUID, int) ([]access.Event, error) {
	return nil, nil
}

var (
	_ access.EventRecorder = (*recEvents)(nil)
	_ access.EventRecorder = (*blockingEvents)(nil)
)
