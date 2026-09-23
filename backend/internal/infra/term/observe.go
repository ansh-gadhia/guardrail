package term

import (
	"sync"
)

// ScrollbackBytes is how much recent output a newly-arrived observer is shown
// before the live stream starts.
//
// A terminal is a stateful picture, not a log: joining a session mid-command and
// seeing only what arrives next shows a supervisor a cursor on a blank screen and
// no idea what the operator has been doing. Replaying the tail reconstructs
// enough of the screen — including the escape sequences that placed the cursor —
// for the view to make sense immediately.
//
// 256 KB is a few thousand lines of ordinary terminal output, which is far more
// than the visible grid and cheap to hold per live session.
const ScrollbackBytes = 256 << 10

// observerQueue is how many pending writes one observer may fall behind by
// before it is dropped.
//
// Dropping is deliberate, and dropping FRAMES would be wrong: a terminal stream
// is escape sequences whose meaning depends on every preceding byte, so a viewer
// missing a chunk renders garbage that looks like device output. Disconnecting
// instead is honest — the console reconnects and gets fresh scrollback, which is
// correct by construction.
const observerQueue = 64

// Observers is the set of read-only viewers watching a live terminal session,
// together with the recent output a new one needs to make sense of it.
//
// The contract that matters: Broadcast is called from the device -> operator copy
// loop and MUST NOT BLOCK. The operator's latency is not allowed to depend on how
// a supervisor's browser is coping, for the same reason the video mirror is
// non-blocking.
type Observers struct {
	mu     sync.Mutex
	subs   map[*Observer]struct{}
	scroll []byte
}

// NewObservers returns an empty registry.
func NewObservers() *Observers { return &Observers{subs: map[*Observer]struct{}{}} }

// Observer is one read-only viewer. Output arrives on C; it closes when the
// session ends or the viewer has fallen too far behind.
type Observer struct {
	C      chan []byte
	closed bool
}

// Attach registers a viewer and returns it along with the scrollback it should
// render first.
//
// Both happen under one lock on purpose. Snapshotting the scrollback and
// subscribing separately would either lose the bytes written in between or show
// them twice, and in a stream of escape sequences either one corrupts the screen.
func (o *Observers) Attach() (*Observer, []byte) {
	ob := &Observer{C: make(chan []byte, observerQueue)}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.subs[ob] = struct{}{}
	back := make([]byte, len(o.scroll))
	copy(back, o.scroll)
	return ob, back
}

// Detach removes a viewer and closes its channel. Safe to call twice.
func (o *Observers) Detach(ob *Observer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.remove(ob)
}

// remove must be called with the lock held.
func (o *Observers) remove(ob *Observer) {
	if _, ok := o.subs[ob]; !ok {
		return
	}
	delete(o.subs, ob)
	if !ob.closed {
		ob.closed = true
		close(ob.C)
	}
}

// Broadcast records output in the scrollback and fans it out to every viewer.
//
// Never blocks: a viewer whose queue is full is dropped rather than waited for.
func (o *Observers) Broadcast(b []byte) {
	if len(b) == 0 {
		return
	}
	// The caller owns b — it is a reusable read buffer — so anything kept beyond
	// this call is a copy.
	cp := make([]byte, len(b))
	copy(cp, b)

	o.mu.Lock()
	defer o.mu.Unlock()

	o.scroll = append(o.scroll, cp...)
	if n := len(o.scroll) - ScrollbackBytes; n > 0 {
		// Keep the tail. Copying into a fresh slice rather than reslicing stops
		// the backing array growing without bound for the life of the session.
		tail := make([]byte, ScrollbackBytes)
		copy(tail, o.scroll[n:])
		o.scroll = tail
	}

	for ob := range o.subs {
		select {
		case ob.C <- cp:
		default:
			o.remove(ob)
		}
	}
}

// Count reports how many viewers are currently attached.
func (o *Observers) Count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.subs)
}

// CloseAll drops every viewer. Called when the session ends, so a supervisor's
// window closes with it rather than hanging on a stream that will never move.
func (o *Observers) CloseAll() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for ob := range o.subs {
		o.remove(ob)
	}
}
