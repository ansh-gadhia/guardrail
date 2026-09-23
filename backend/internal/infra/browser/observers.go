package browser

import "sync"

// frameObservers fans screencast frames out to read-only supervisors.
//
// # WHY THIS IS NOT term.Observers
//
// A terminal is reconstructed by replaying bytes: the tail of the stream IS the
// screen, so the terminal registry keeps an append-only scrollback. A screencast
// is the opposite — every frame is a complete JPEG, so all a new viewer needs is
// the most recent one, and keeping the others would be holding megabytes of
// superseded pictures to show nobody.
//
// The contract they share is the one that matters: Broadcast is called from the
// screencast callback and must never block, because the operator's frame rate
// cannot be allowed to depend on how a supervisor's browser is coping.
type frameObservers struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
	last []byte
}

// observerQueue is how many frames one viewer may fall behind by. Small on
// purpose: for video, stale frames are worthless — a viewer who cannot keep up
// should jump to the present rather than replay a backlog.
const observerQueue = 4

func newFrameObservers() *frameObservers {
	return &frameObservers{subs: map[chan []byte]struct{}{}}
}

// Attach registers a viewer and returns it with the current frame, so a
// supervisor sees the screen immediately instead of waiting for the next repaint
// — which, on a device nobody is touching, may never come.
func (f *frameObservers) Attach() (chan []byte, []byte) {
	ch := make(chan []byte, observerQueue)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs[ch] = struct{}{}
	return ch, f.last
}

func (f *frameObservers) Detach(ch chan []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remove(ch)
}

// remove must be called with the lock held.
func (f *frameObservers) remove(ch chan []byte) {
	if _, ok := f.subs[ch]; !ok {
		return
	}
	delete(f.subs, ch)
	close(ch)
}

// Broadcast records the frame as current and offers it to every viewer. A viewer
// whose queue is full is dropped rather than waited for.
func (f *frameObservers) Broadcast(frame []byte) {
	if len(frame) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = frame
	for ch := range f.subs {
		select {
		case ch <- frame:
		default:
			f.remove(ch)
		}
	}
}

// CloseAll drops every viewer, so a supervisor's window closes with the session
// rather than freezing on its last frame.
func (f *frameObservers) CloseAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		f.remove(ch)
	}
}

func (f *frameObservers) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}
