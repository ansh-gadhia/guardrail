package browser

import "testing"

// TestPushFrameKeepsNewest pins the live-viewer drop policy: when the buffer is
// full, pushFrame discards the OLDEST queued frame so the newest always survives
// and lands last. Dropping the wrong end (or dropping the incoming frame, the old
// behaviour) would make a slow viewer replay stale frames instead of catching up.
func TestPushFrameKeepsNewest(t *testing.T) {
	bs := &bSession{frames: make(chan []byte, 2)}

	// Push more frames than the buffer can hold, with no reader draining.
	for i := 0; i < 6; i++ {
		pushFrame(bs, []byte{byte(i)})
	}

	// The buffer should hold exactly its capacity, ending on the newest frame.
	var drained []byte
	for {
		select {
		case f := <-bs.frames:
			drained = append(drained, f[0])
			continue
		default:
		}
		break
	}
	if len(drained) != 2 {
		t.Fatalf("buffer held %d frames, want 2 (cap): %v", len(drained), drained)
	}
	if last := drained[len(drained)-1]; last != 5 {
		t.Errorf("newest frame not retained: last drained = %d, want 5", last)
	}
	if drained[0] != 4 {
		t.Errorf("expected the two newest frames [4 5], got %v", drained)
	}
}

// TestPushFrameNeverBlocks: the screencast callback must never stall on a viewer,
// so pushFrame returns even when the buffer is full and nothing is reading.
func TestPushFrameNeverBlocks(t *testing.T) {
	bs := &bSession{frames: make(chan []byte, 1)}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			pushFrame(bs, []byte{1})
		}
		close(done)
	}()
	<-done // a hang here (test timeout) means pushFrame blocked
}
