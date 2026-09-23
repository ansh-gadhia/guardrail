package guacgw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"

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
		// Said out loud, with the reason. "could not join the desktop" is all the
		// console can show, and on its own it sends you looking at the join logic
		// when the cause may be nothing of the sort — a full disk stopping guacd
		// writing its recording presents exactly this way.
		if g.deps.Log != nil {
			g.deps.Log.Warn("guac: a supervisor could not join a live desktop",
				zap.String("session_id", sid.String()),
				zap.String("guacd_connection", connID),
				zap.Error(err))
		}
		// The operator's session is untouched by this failing — only the watcher
		// is turned away, with the code the console reads as "nothing to watch".
		_ = c.Close(term.CloseDeviceGone, "could not join the desktop")
		return true
	}
	defer func() { _ = join.Close() }()

	// Counted only once the join has actually succeeded, so a watcher guacd
	// refused never shows up on the operator's screen as somebody looking.
	s.mu.Lock()
	s.watchers++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.watchers--
		s.mu.Unlock()
	}()

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

	// Supervisor -> guacd, FILTERED — not discarded.
	//
	// Discarding everything was the first version, and it looked right: a watcher
	// has nothing to say. It lasted about fifteen seconds. guacd sends `sync` and
	// requires every user of a connection to echo it; one that does not is
	// "not responding" and is disconnected — guacd logged exactly that, and the
	// console showed "The desktop could not be opened. Aborted." The tunnel's own
	// keepalive was going unanswered too, and the client closes after 15s of that.
	//
	// So a watcher's messages are split like the operator's and then held to an
	// allowlist: the protocol's own bookkeeping goes through, anything that could
	// move, type into, resize or read the desktop does not. See splitWatcherMessage.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			forward, replies, err := splitWatcherMessage(data)
			if err != nil {
				return
			}
			if len(replies) > 0 {
				if err := c.Write(ctx, websocket.MessageText, replies); err != nil {
					return
				}
			}
			// Deliberately no Activity.Touch: a watcher's sync replies are not the
			// operator working, and counting them would stop an abandoned session
			// ever idling out for as long as somebody watched it.
			if len(forward) == 0 {
				continue
			}
			if _, err := join.Write(forward); err != nil {
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

// watcherOpcodes is everything a WATCHER may send on to guacd.
//
// An allowlist, because the failure modes are not symmetrical: an opcode missing
// from here costs a watcher their view, which is loud and gets reported; an
// opcode wrongly allowed puts a supervisor's hands on somebody else's desktop,
// which is silent and is the one thing this path exists to prevent.
//
//	sync  echoes guacd's frame markers. Required: a user who never answers is
//	      "not responding" and is disconnected.
//	ack   acknowledges a stream guacd is sending TO this user — the images the
//	      display is drawn from. Flow control for the watcher's own view.
//	nop   keepalive, no effect.
//
// Deliberately absent: mouse, key, clipboard, size (which would resize the
// OPERATOR's desktop to the watcher's window on a shared connection), put, file,
// pipe, argv, audio, and disconnect — closing the socket is how a watcher leaves.
var watcherOpcodes = map[string]bool{"sync": true, "ack": true, "nop": true}

// splitWatcherMessage is splitClientMessage held to watcherOpcodes: tunnel pings
// are answered, protocol bookkeeping is forwarded, and everything else is dropped.
func splitWatcherMessage(data []byte) (forward, replies []byte, err error) {
	all, replies, err := splitClientMessage(data)
	if err != nil {
		return nil, nil, err
	}
	r := newReader(bytes.NewReader(all))
	for {
		in, rerr := r.ReadInstruction()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return forward, replies, nil
			}
			return nil, nil, rerr
		}
		if watcherOpcodes[in.Opcode] {
			forward = append(forward, in.String()...)
		}
	}
}

// WatcherCount reports how many supervisors are joined to a live desktop.
func (g *Gateway) WatcherCount(sid uuid.UUID) (int, bool) {
	g.mu.RLock()
	s := g.sessions[sid]
	g.mu.RUnlock()
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watchers, true
}
