package browser

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
)

/* The session activity timeline.

   A recording answers "what did the screen look like"; the timeline answers
   "what did they DO", and a reviewer needs both — the second is what makes the
   first searchable. For a long time this captured one thing only: a main-frame
   navigation. That is close to nothing on the devices GuardRail actually fronts.
   A firewall or switch admin UI is a single-page app: it loads once, and every
   subsequent action — opening a policy, editing a rule, pushing a config — is an
   in-page route change or an XHR. So a 53-second session in which somebody
   changed a firewall rule produced exactly one timeline entry, "GET /", and the
   reviewer was left with a video and no index into it.

   What is captured now is everything the browser can see that a reviewer would
   ask about: navigations (real and in-page), state-changing requests, file
   downloads, and device dialogs.

   Writes go through here rather than straight to the recorder for three reasons,
   each of which was a real problem:

     - The screencast callback must never block. The old code spawned a fresh
       goroutine per navigation to avoid that; a page that redirects in a loop
       spawns them unboundedly. This is one goroutine and a bounded queue that
       drops rather than grows.
     - Admin UIs poll. Without coalescing, a dashboard that re-POSTs its status
       endpoint every two seconds buries the one request that mattered.
     - A session must not be able to write unbounded rows into the database. */

const (
	// tlQueue is the depth of the hand-off buffer. Deep enough to absorb the
	// burst a page load produces, shallow enough that a stalled database costs
	// memory in kilobytes rather than megabytes.
	tlQueue = 256
	// tlMaxEvents caps one session's timeline. Reached only by a page in a loop;
	// a human-driven session lands two orders of magnitude below it.
	tlMaxEvents = 2000
	// tlDedupeWindow is how long an identical action is treated as the same one.
	// Sized for polling UIs (seconds), not for a person clicking the same button
	// twice deliberately (which is slower than this, and shows up twice).
	tlDedupeWindow = 10 * time.Second
	// tlSeenCap bounds the dedupe map so a session that visits thousands of
	// distinct paths cannot grow it without limit.
	tlSeenCap = 512
	// tlWriteTimeout bounds one database write. The timeline is best-effort: a
	// slow write is abandoned rather than allowed to back the queue up.
	tlWriteTimeout = 5 * time.Second
	// tlDrainGrace is how long End waits for queued events to reach the database
	// before giving up on them, so the last actions of a session are not lost to
	// the teardown that follows them.
	tlDrainGrace = 5 * time.Second
)

type tlEvent struct {
	kind string
	data map[string]any
}

// timeline is one session's activity writer. A nil *timeline is usable and
// discards everything, so callers never need a nil check at the call site.
type timeline struct {
	ch        chan tlEvent
	done      chan struct{}
	closeOnce sync.Once

	mu      sync.Mutex
	seen    map[string]time.Time
	written int
	dropped int
}

// newTimeline starts the writer for one session. It returns nil when there is no
// recorder to write to, which is a supported configuration (the gateway still
// serves sessions, it just keeps no timeline).
func newTimeline(rec access.EventRecorder, sessionID uuid.UUID, log *zap.Logger) *timeline {
	if rec == nil {
		return nil
	}
	t := &timeline{
		ch:   make(chan tlEvent, tlQueue),
		done: make(chan struct{}),
		seen: make(map[string]time.Time, 64),
	}
	go func() {
		defer close(t.done)
		for ev := range t.ch {
			ctx, cancel := context.WithTimeout(context.Background(), tlWriteTimeout)
			err := rec.RecordEvent(ctx, sessionID, ev.kind, ev.data)
			cancel()
			if err != nil && log != nil {
				// Debug, not warn: the timeline is an aid, and a session whose
				// database is briefly unavailable should still run. The recording
				// itself is the evidence of record.
				log.Debug("browser: timeline event not recorded",
					zap.String("session_id", sessionID.String()),
					zap.String("kind", ev.kind), zap.Error(err))
			}
		}
	}()
	return t
}

// record queues one event. It never blocks and never fails: on a full queue or
// past the per-session cap the event is dropped and counted.
func (t *timeline) record(kind string, data map[string]any) {
	if t == nil {
		return
	}
	if !t.admit(kind, data) {
		return
	}
	select {
	case t.ch <- tlEvent{kind: kind, data: data}:
	default:
		t.mu.Lock()
		t.dropped++
		t.mu.Unlock()
	}
}

// admit applies the per-session cap and the coalescing window. It reports
// whether this event is new enough to be worth a row.
func (t *timeline) admit(kind string, data map[string]any) bool {
	key := dedupeKey(kind, data)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.written >= tlMaxEvents {
		t.dropped++
		return false
	}
	if last, ok := t.seen[key]; ok && now.Sub(last) < tlDedupeWindow {
		t.seen[key] = last // repeats do not extend the window, so a poll still
		return false       // reappears every tlDedupeWindow rather than never
	}
	if len(t.seen) >= tlSeenCap {
		for k, at := range t.seen {
			if now.Sub(at) >= tlDedupeWindow {
				delete(t.seen, k)
			}
		}
		// Still full: everything in it is recent, so this session is churning
		// through distinct paths. Start over rather than grow.
		if len(t.seen) >= tlSeenCap {
			t.seen = make(map[string]time.Time, 64)
		}
	}
	t.seen[key] = now
	t.written++
	return true
}

// close stops the writer and waits, briefly, for what is queued to be written.
func (t *timeline) close() {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() { close(t.ch) })
	select {
	case <-t.done:
	case <-time.After(tlDrainGrace):
	}
}

// stats reports what was written and what was discarded. Test-facing.
func (t *timeline) stats() (written, dropped int) {
	if t == nil {
		return 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.written, t.dropped
}

// dedupeKey identifies "the same action again". Only the fields that make an
// action distinct take part: two POSTs to the same endpoint are the same action
// whether or not their bodies differ, because the body is not on the timeline.
func dedupeKey(kind string, data map[string]any) string {
	var b strings.Builder
	b.WriteString(kind)
	for _, f := range [...]string{"method", "path", "message", "filename"} {
		if s, ok := data[f].(string); ok && s != "" {
			b.WriteByte('\x00')
			b.WriteString(s)
		}
	}
	return b.String()
}

// pathOf reduces a URL to the part worth showing on a timeline: path and query.
// A reviewer scanning fifty rows is looking for "which page", and the scheme and
// host are the same for every row in a session — they push the part that differs
// off the end of the line. The full URL is kept alongside for the ones that need
// it (a download, an off-device request).
func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// stateChanging reports whether an HTTP method is one that alters the device.
// These are the requests a reviewer is looking for: a GET is somebody looking, a
// POST/PUT/PATCH/DELETE is somebody changing the box.
func stateChanging(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// pageFurniture reports whether a resource type is something the page fetched
// for itself rather than something the operator did. Images, fonts and
// stylesheets are never an action; XHR, fetch and documents can be.
func pageFurniture(rt network.ResourceType) bool {
	switch rt {
	case network.ResourceTypeImage,
		network.ResourceTypeStylesheet,
		network.ResourceTypeFont,
		network.ResourceTypeMedia,
		network.ResourceTypeTextTrack,
		network.ResourceTypeManifest,
		network.ResourceTypePing,
		network.ResourceTypeCSPViolationReport,
		network.ResourceTypePrefetch,
		network.ResourceTypeSignedExchange,
		network.ResourceTypePreflight:
		return true
	default:
		return false
	}
}
