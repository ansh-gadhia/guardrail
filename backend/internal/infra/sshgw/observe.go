package sshgw

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// Observe streams a live session to a supervisor, read-only.
//
// # WHY THIS IS NOT Stream
//
// Opening somebody else's session used to be impossible and looked like a bug:
// the console navigated to /proxy/<sid>/, the proxy cookie is minted per session
// for the operator who connected, so a supervisor got 401. Handing them that
// cookie would have been worse — Stream reattaches by calling client.NewSession(),
// which opens a FRESH SSH channel with a fresh PTY. They would have got a new
// shell on the same host, seen none of the operator's work, and been typing into
// a second session nobody was watching. The one thing a supervisor must not get
// from "watch this session" is a second unsupervised session.
//
// So observation is a separate path with different properties:
//
//   - It does not touch `attached`. Watching is not typing; it does not contend
//     with the operator's terminal and any number of people may watch at once.
//   - It reads from the fan-out in emit, so it sees exactly the bytes the
//     operator sees — the same stream the transcript records.
//   - Inbound frames are read and DISCARDED. Not ignoring them would put a second
//     keyboard on the PTY and make the transcript a lie about who typed what.
//   - It never writes to the device, so it cannot extend an idle session: no
//     Touch here, deliberately. A session must not stay alive because somebody is
//     watching it.
//
// Authentication is the caller's job — the API handler checks the permission and
// audits the attach before calling this. The organisation is re-checked here
// anyway: a gateway that hands over a session on the strength of an id alone is
// one bug in a handler away from a cross-tenant leak.
func (g *Gateway) Observe(w http.ResponseWriter, r *http.Request, sid, orgID uuid.UUID) bool {
	s := g.observable(sid, orgID)
	if s == nil {
		return false
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // the handshake already responded
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(term.MaxInputBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ob, scrollback := s.obs.Attach()
	defer s.obs.Detach(ob)

	// The screen as it stands, before the live stream. Without it a supervisor
	// joining mid-command sees a cursor on an empty page.
	if len(scrollback) > 0 {
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.Write(wctx, websocket.MessageBinary, scrollback)
		wcancel()
		if err != nil {
			return true
		}
	}

	// Read and discard. A viewer's keystrokes go nowhere, but the socket still has
	// to be read: an unread peer eventually fills its buffer and the connection
	// stalls instead of closing cleanly, and a close frame would never be noticed.
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
		case b, open := <-ob.C:
			if !open {
				// Either the session ended or this viewer fell too far behind. The
				// console tells the two apart by asking the API for session status.
				_ = c.Close(term.CloseDeviceGone, "session ended or viewer fell behind")
				return true
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			werr := c.Write(wctx, websocket.MessageBinary, b)
			wcancel()
			if werr != nil {
				return true
			}
		}
	}
}

// observable finds a live session by id within one organisation.
//
// Deliberately NOT lookup(): that one demands the per-session proxy token, which
// is exactly what a supervisor does not have and must not be given.
func (g *Gateway) observable(sessionID, orgID uuid.UUID) *sshSession {
	g.mu.RLock()
	s := g.sessions[sessionID]
	g.mu.RUnlock()
	if s == nil || s.orgID != orgID || time.Now().After(s.expires) {
		return nil
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil
	}
	return s
}
