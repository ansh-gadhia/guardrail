package browser

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// Observe streams an isolated web session to a supervisor, read-only.
//
// An isolated session is a headless Chromium rendering the device, screencast to
// the operator as JPEG frames. Watching it is a fan-out of those frames — which
// is only possible because each frame is complete in itself: unlike a desktop's
// differential drawing instructions, one frame IS the screen, so a supervisor
// arriving mid-session is shown the current one and is immediately correct.
//
// Input is read and discarded. The operator's stream carries mouse, keyboard,
// paste and dialog answers into the real browser; none of that is forwarded
// here, because a second person typing into one headless tab is indistinguishable
// in the recording from the operator doing it.
func (g *Gateway) Observe(w http.ResponseWriter, r *http.Request, sid, orgID uuid.UUID) bool {
	bs := g.observable(sid, orgID)
	if bs == nil {
		return false
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	defer func() { _ = c.CloseNow() }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ch, current := bs.obs.Attach()
	defer bs.obs.Detach(ch)

	// The screen as it stands. On a device nobody is touching there may be no
	// repaint for minutes, so without this a supervisor would stare at nothing
	// and conclude the feature is broken.
	if len(current) > 0 {
		wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
		err := c.Write(wctx, websocket.MessageBinary, current)
		wcancel()
		if err != nil {
			return true
		}
	}

	// Read and discard: watching is not driving. Reading is still required — an
	// unread peer stalls rather than closing, and the close frame would never be
	// seen.
	go func() {
		for {
			if _, _, rerr := c.Read(ctx); rerr != nil {
				cancel()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "")
			return true
		case frame, open := <-ch:
			if !open {
				_ = c.Close(term.CloseDeviceGone, "session ended or viewer fell behind")
				return true
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			werr := c.Write(wctx, websocket.MessageBinary, frame)
			wcancel()
			if werr != nil {
				return true
			}
		}
	}
}

// ObserveConsole serves the page a supervisor watches an isolated session in.
//
// The operator's own canvas viewer, in read-only mode: same rendering, same
// frames, with the input handlers left unbound and a banner saying so.
func (g *Gateway) ObserveConsole(w http.ResponseWriter, _ *http.Request, sid, orgID uuid.UUID) bool {
	bs := g.observable(sid, orgID)
	if bs == nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(observePage(sid.String(), bs.w, bs.h)))
	return true
}

// observable finds a live isolated session by id within one organisation.
//
// Deliberately not lookup(): that demands the operator's per-session token,
// which a supervisor does not have and must not be given.
func (g *Gateway) observable(sessionID, orgID uuid.UUID) *bSession {
	g.mu.RLock()
	bs := g.sessions[sessionID]
	g.mu.RUnlock()
	if bs == nil || bs.orgID != orgID || time.Now().After(bs.expires) || bs.obs == nil {
		return nil
	}
	return bs
}
