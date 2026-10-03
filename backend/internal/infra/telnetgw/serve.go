package telnetgw

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// Console serves the terminal page for a session.
func (g *Gateway) Console(w http.ResponseWriter, _ *http.Request, sid uuid.UUID, token string, _ string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(term.Page(term.Options{
		SessionID: sid.String(),
		Device:    s.deviceLabel,
		Watermark: s.watermark,
		Protocol:  "Telnet",
	})))
	return true
}

// operatorQueue is how many chunks of output the operator's window may fall
// behind by before it is caught up from the scrollback instead.
const operatorQueue = 256

func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}
	if s.isClosed() {
		http.Error(w, "session is over", http.StatusGone)
		return true
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(term.MaxInputBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// One keyboard per session: this window takes it, and whichever had it is
	// closed with CloseTakenOver.
	// Two contexts, for the reason sshgw's Stream gives: cancelling one a Read is
	// waiting on makes the websocket library drop the connection, so the window
	// being replaced could never be told why. ctx carries reads and writes; view
	// is what a newer window cancels, and is only ever waited on.
	view, viewCancel := context.WithCancel(ctx)
	defer viewCancel()
	gen := s.takeOver(viewCancel)
	defer s.release(gen)
	go term.KeepAlive(ctx, c, term.KeepAliveInterval)

	done, err := g.ensureConn(ctx, s)
	if err != nil {
		_ = c.Close(term.CloseDeviceGone, "could not reach the device")
		return true
	}

	ob, screen := s.op.AttachQueue(operatorQueue)
	defer s.op.Detach(ob)
	// The screen as it stands — the login, and everything since.
	if len(screen) > 0 {
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		werr := c.Write(wctx, websocket.MessageBinary, screen)
		wcancel()
		if werr != nil {
			return true
		}
	}

	left := make(chan struct{})
	go func() {
		defer close(left)
		for {
			typ, data, rerr := c.Read(ctx)
			if rerr != nil {
				return
			}
			if typ == websocket.MessageText {
				g.dispatch(s, data)
			}
		}
	}()

	for {
		select {
		case b, open := <-ob.C:
			if !open {
				if s.isClosed() {
					_ = c.Close(websocket.StatusNormalClosure, "")
					return true
				}
				// Fell too far behind; reattaching catches up from the scrollback.
				_ = c.Close(websocket.StatusTryAgainLater, "catching up")
				return true
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			werr := c.Write(wctx, websocket.MessageBinary, b)
			wcancel()
			if werr != nil {
				return true
			}
		case <-done:
			for flushed := false; !flushed; {
				select {
				case b, open := <-ob.C:
					if !open {
						flushed = true
						break
					}
					wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
					_ = c.Write(wctx, websocket.MessageBinary, b)
					wcancel()
				default:
					flushed = true
				}
			}
			s.mu.Lock()
			connErr := s.connErr
			s.mu.Unlock()
			if s.isClosed() || isSessionOver(connErr) {
				// The device hung up cleanly (an `exit`, an exec-timeout) or the
				// session was torn down: nothing to reconnect to right now.
				_ = c.Close(websocket.StatusNormalClosure, "")
			} else {
				_ = c.Close(term.CloseDeviceGone, "device connection lost")
			}
			return true
		case <-left:
			// The window went away. The device connection does not: it carries on
			// for the session, recorded and watchable, for the next window.
			return true
		case <-view.Done():
			if s.superseded(gen) {
				_ = c.Close(term.CloseTakenOver, "opened in another window")
			}
			return true
		}
	}
}

// ensureConn returns the done channel of the session's device connection,
// dialling one if it has none — the device hung up since the last window, and
// this window is the reconnect.
func (g *Gateway) ensureConn(ctx context.Context, s *telnetSession) (<-chan struct{}, error) {
	// One dial at a time: two windows attaching together to a session whose
	// connection had dropped would otherwise both log in to the device.
	s.dialMu.Lock()
	defer s.dialMu.Unlock()
	s.mu.Lock()
	if s.conn != nil {
		done := s.connDone
		s.mu.Unlock()
		return done, nil
	}
	redial := s.dialed
	s.mu.Unlock()
	if err := g.dial(ctx, s); err != nil {
		return nil, err
	}
	if redial && g.deps.Events != nil {
		_ = g.deps.Events.RecordEvent(ctx, s.id, "telnet_reconnect", map[string]any{"host": s.deviceLabel})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connDone, nil
}

// dispatch applies one message from the operator's window.
func (g *Gateway) dispatch(s *telnetSession, data []byte) {
	m, ok := term.ParseClientMsg(data)
	if !ok {
		return // ignore malformed frames rather than killing the session
	}
	s.mu.Lock()
	dev := s.conn
	s.mu.Unlock()
	switch m.T {
	case term.MsgInput:
		// Typing is what proves an operator is still there. A resize is not: a
		// window manager can emit one with nobody at the keyboard, so counting it
		// as activity would keep an abandoned session alive past its idle timeout.
		g.touch(s)
		// Before the device sees it; see sshgw.
		s.cmds.Input([]byte(m.D))
		if dev != nil {
			// A connection that has just ended refuses the write; its end reaches
			// the window through the done channel, not through this.
			_, _ = dev.Write([]byte(m.D))
		}
	case term.MsgResize:
		if m.Cols <= 0 || m.Rows <= 0 {
			return
		}
		s.mu.Lock()
		s.cols, s.rows = m.Cols, m.Rows
		s.mu.Unlock()
		if s.rec != nil {
			s.rec.Resize(m.Cols, m.Rows)
		}
		if s.mirror != nil {
			s.mirror.Resize(m.Cols, m.Rows)
		}
		s.cmds.Resize(m.Cols, m.Rows)
		if dev != nil {
			_ = dev.Resize(m.Cols, m.Rows)
		}
	}
}

// touch marks the session as in use for the idle reaper.
func (g *Gateway) touch(s *telnetSession) {
	if g.deps.Activity != nil {
		g.deps.Activity.Touch(s.id)
	}
}

// isSessionOver reports whether an error means the session ended rather than
// broke.
//
// The distinction decides whether the console offers to reconnect, and it is
// genuinely ambiguous on a telnet socket: an operator typing `exit` and an IOS
// exec-timeout both arrive as a clean EOF, indistinguishable at the byte level.
// EOF is therefore treated as "over". That is the safe way to be wrong: the cost
// is one click on Reconnect, whereas guessing "broken" would have GuardRail
// silently dial back into a router and re-authenticate with nobody watching.
func isSessionOver(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return true
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	return false
}
