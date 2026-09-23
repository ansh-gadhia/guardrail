package term

import (
	"bytes"
	"sync"
	"testing"
)

// A viewer that arrives mid-session must see what is already on the screen.
func TestObserverGetsScrollbackOnAttach(t *testing.T) {
	o := NewObservers()
	o.Broadcast([]byte("before-"))
	o.Broadcast([]byte("you-joined"))

	ob, back := o.Attach()
	defer o.Detach(ob)
	if string(back) != "before-you-joined" {
		t.Fatalf("scrollback = %q, want the whole session so far", back)
	}

	o.Broadcast([]byte("|live"))
	if got := string(<-ob.C); got != "|live" {
		t.Fatalf("live write = %q", got)
	}
}

// Scrollback is bounded, and it is the TAIL that is kept — the recent screen is
// what reconstructs the view, not the start of the session.
func TestScrollbackKeepsTheTailAndIsBounded(t *testing.T) {
	o := NewObservers()
	o.Broadcast(bytes.Repeat([]byte("x"), ScrollbackBytes))
	o.Broadcast([]byte("THE-END"))

	_, back := o.Attach()
	if len(back) != ScrollbackBytes {
		t.Fatalf("scrollback = %d bytes, want it capped at %d", len(back), ScrollbackBytes)
	}
	if !bytes.HasSuffix(back, []byte("THE-END")) {
		t.Fatal("the most recent output was dropped; scrollback kept the wrong end")
	}
}

// The property the whole design rests on: a supervisor's slow browser must not
// hold up the operator's terminal.
func TestBroadcastNeverBlocksOnASlowObserver(t *testing.T) {
	o := NewObservers()
	ob, _ := o.Attach()

	// Never read from ob.C. Well past the queue depth.
	for i := 0; i < observerQueue*4; i++ {
		o.Broadcast([]byte("output"))
	}
	if o.Count() != 0 {
		t.Fatal("an observer that stopped reading is still attached; it would wedge the copy loop")
	}
	if _, open := <-ob.C; open {
		// Drain: the channel holds buffered writes, then must be closed.
		for range ob.C { //nolint:revive // draining
		}
	}
}

// A dropped or detached observer must have its channel closed, so the socket
// pump ends rather than hanging on a stream that will never move again.
func TestDetachClosesTheChannelAndIsIdempotent(t *testing.T) {
	o := NewObservers()
	ob, _ := o.Attach()
	o.Detach(ob)
	if _, open := <-ob.C; open {
		t.Fatal("Detach left the channel open")
	}
	o.Detach(ob) // must not panic on a double close
	if o.Count() != 0 {
		t.Fatalf("Count = %d after Detach", o.Count())
	}
}

// Ending the session closes every viewer.
func TestCloseAllDropsEveryObserver(t *testing.T) {
	o := NewObservers()
	a, _ := o.Attach()
	b, _ := o.Attach()
	if o.Count() != 2 {
		t.Fatalf("Count = %d, want 2", o.Count())
	}
	o.CloseAll()
	for _, ob := range []*Observer{a, b} {
		if _, open := <-ob.C; open {
			t.Fatal("CloseAll left a viewer attached to a dead session")
		}
	}
}

// Broadcast copies: the caller's buffer is a reusable read buffer and will be
// overwritten before a slow viewer ever looks at it.
func TestBroadcastDoesNotAliasTheCallersBuffer(t *testing.T) {
	o := NewObservers()
	ob, _ := o.Attach()
	buf := []byte("first")
	o.Broadcast(buf)
	copy(buf, []byte("SECON"))
	if got := string(<-ob.C); got != "first" {
		t.Fatalf("observer saw %q — Broadcast aliased the caller's buffer", got)
	}
}

func TestObserversAreRaceSafe(t *testing.T) {
	o := NewObservers()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ob, _ := o.Attach()
			for range 20 {
				select {
				case <-ob.C:
				default:
				}
			}
			o.Detach(ob)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			o.Broadcast([]byte("tick"))
		}
	}()
	wg.Wait()
	o.CloseAll()
}
