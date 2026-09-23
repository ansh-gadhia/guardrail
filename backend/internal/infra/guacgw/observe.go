package guacgw

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// Observe streams a live desktop to a supervisor, read-only.
//
// # WHY THIS JOINS RATHER THAN FANS OUT
//
// A terminal can be watched by copying bytes to extra viewers, because a
// terminal stream is the whole truth: replay the tail and you have reconstructed
// the screen. A desktop is not. Guacamole instructions are differential — they
// draw the rectangles that CHANGED — so a viewer who starts reading mid-stream
// sees updates to a picture they never received and renders a black screen with
// a moving cursor on it.
//
// guacd already solves this. `select $<connection id>` joins an existing
// connection instead of starting a new one, and guacd sends the joining client
// the current display state before the live updates. It is the mechanism
// Guacamole's own screen sharing is built on, and it means the supervisor's
// first frame is the desktop as it actually looks.
//
// Read-only is enforced by never forwarding what the supervisor sends. guacd
// would happily accept their mouse and keyboard on a joined connection — that is
// what makes Guacamole's sharing collaborative — so the restraint has to be
// here. Input is read and discarded, exactly as on the terminal gateways.
func (g *Gateway) Observe(w http.ResponseWriter, r *http.Request, sid, orgID uuid.UUID) bool {
	s := g.observable(sid, orgID)
	if s == nil {
		return false
	}
	s.mu.Lock()
	connID := s.connID
	s.mu.Unlock()
	if connID == "" {
		// Live but with no joinable connection: the desktop handshake has not
		// finished, or this is a session restored without one.
		return false
	}

	// The subprotocol is not optional — guacamole-common-js opens the tunnel with
	// `new WebSocket(url, "guacamole")` and fails the connection if the server
	// selects nothing.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{"guacamole"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return true // handshake already responded
	}
	c.SetReadLimit(maxClientBytes)
	defer func() { _ = c.CloseNow() }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// A second connection to guacd, joining the first. Empty parameters: a join
	// inherits the connection's own, and guacd fills the slots it lists from the
	// session already running.
	join, err := dialGuacd(ctx, g.cfg.Addr, connConfig{
		Protocol: joinTarget(connID),
		Width:    g.cfg.Width, Height: g.cfg.Height, DPI: g.cfg.DPI,
		Params: map[string]string{},
	}, g.cfg.HandshakeTimeout, g.tlsCfg)
	if err != nil {
		// The operator's session is untouched by this failing — only the watcher
		// is turned away, with the code the console reads as "nothing to watch".
		_ = c.Close(term.CloseDeviceGone, "could not join the desktop")
		return true
	}
	defer func() { _ = join.Close() }()

	done := make(chan struct{}, 2)

	// guacd -> supervisor. Framed on instruction boundaries for the same reason
	// the operator's stream is: the client parses each message as a whole number
	// of complete instructions and closes the tunnel on a partial one, and a large
	// img/blob crosses any fixed read buffer as a matter of course.
	go func() {
		defer func() { done <- struct{}{} }()
		batch := make([]byte, 0, 32<<10)
		for {
			in, err := join.r.ReadInstruction()
			if err != nil {
				return
			}
			batch = append(batch, in.String()...)
			if len(batch) >= 16<<10 || join.r.Buffered() == 0 {
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := c.Write(wctx, websocket.MessageText, batch)
				wcancel()
				if err != nil {
					return
				}
				batch = batch[:0]
			}
		}
	}()

	// Supervisor -> nowhere. Read and discarded: guacd would accept their input on
	// a joined connection, and watching must not become driving. Reading is not
	// optional — an unread peer stalls instead of closing, and a close frame would
	// never be noticed.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
	return true
}

// ObserveConsole declines: a desktop has no server-rendered page.
//
// The operator's own viewer is the React DesktopPlayer, decoding drawing
// instructions onto a canvas in the console app, and the watch page mounts that
// same component against the observe socket. Returning a page here would mean a
// second renderer to keep in step with the first, and returning a JSON
// description would put a raw response body in an iframe — which is precisely
// the bug that made "Open somebody else's session" show pretty-printed JSON.
func (g *Gateway) ObserveConsole(_ http.ResponseWriter, _ *http.Request, _, _ uuid.UUID) bool {
	return false
}

// observable finds a live session by id within one organisation.
//
// Deliberately not lookup(): that demands the operator's per-session token,
// which is exactly what a supervisor does not have and must not be given.
func (g *Gateway) observable(sessionID, orgID uuid.UUID) *guacSession {
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

// joinTarget renders a connection id as the argument `select` takes to JOIN it.
//
// guacd already returns the id with its "$" — the ready reply is
// `ready,$bc1d53ad-...` — so prefixing unconditionally produced "$$bc1d53ad-..."
// and guacd refused it. Normalising here rather than at the call site means the
// prefix is applied exactly once however the id was obtained.
func joinTarget(connID string) string {
	if strings.HasPrefix(connID, "$") {
		return connID
	}
	return "$" + connID
}
