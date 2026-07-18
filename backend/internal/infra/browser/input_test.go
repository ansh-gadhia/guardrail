package browser

import "testing"

func mv(x float64) inputMsg  { return inputMsg{T: "m", E: "move", X: x} }
func down(x float64) inputMsg { return inputMsg{T: "m", E: "down", X: x} }

// TestCoalesceMovesKeepsNewest: a run of queued moves collapses to the most
// recent, so the cursor jumps to where the operator actually is instead of
// replaying every intermediate position at ~16ms each.
func TestCoalesceMovesKeepsNewest(t *testing.T) {
	in := make(chan inputMsg, 8)
	in <- mv(2)
	in <- mv(3)
	in <- mv(4)
	got, pushback := coalesceMoves(in, mv(1))
	if got.X != 4 {
		t.Errorf("coalesced move X = %v, want 4 (newest)", got.X)
	}
	if pushback != nil {
		t.Errorf("unexpected pushback %+v", pushback)
	}
	if len(in) != 0 {
		t.Errorf("channel not drained, %d left", len(in))
	}
}

// TestCoalesceMovesStopsAtNonMove: coalescing must not swallow or reorder a click
// that arrived mid-drag — it stops at the non-move and hands it back intact, and
// anything after it stays queued in order.
func TestCoalesceMovesStopsAtNonMove(t *testing.T) {
	in := make(chan inputMsg, 8)
	in <- mv(2)
	in <- down(3) // a click lands during the move stream
	in <- mv(5)   // and movement continues after it
	got, pushback := coalesceMoves(in, mv(1))
	if got.X != 2 {
		t.Errorf("dispatched move X = %v, want 2 (last move before the click)", got.X)
	}
	if pushback == nil || pushback.E != "down" || pushback.X != 3 {
		t.Errorf("click was dropped or altered: %+v", pushback)
	}
	// The post-click move must still be waiting, undisturbed.
	if len(in) != 1 {
		t.Fatalf("expected 1 event still queued, got %d", len(in))
	}
	if n := <-in; n.E != "move" || n.X != 5 {
		t.Errorf("queued-after-click event = %+v, want move X=5", n)
	}
}

// TestCoalesceMovesNoBacklog: with nothing queued, the current move dispatches
// unchanged and the call never blocks.
func TestCoalesceMovesNoBacklog(t *testing.T) {
	in := make(chan inputMsg, 1)
	got, pushback := coalesceMoves(in, mv(7))
	if got.X != 7 || pushback != nil {
		t.Errorf("got %+v, pushback %+v; want move X=7, no pushback", got, pushback)
	}
}
