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
func (g *Gateway) Console(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token, path string) bool {
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

// Stream bridges the operator's WebSocket to the device.
//
// It is also the reconnect path. If the device connection is gone but the access
// session is still live and still authorised, attaching dials the device again
// and re-authenticates from the vault. That is what makes the console's
// Reconnect button work without the operator ever holding a credential.
func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}

	// One terminal per session. Without this a second tab would attach to the
	// same device connection, interleaving two people's keystrokes into one
	// transcript that attributes everything to whoever opened the session.
	s.mu.Lock()
	if s.attached || s.closed {
		s.mu.Unlock()
		http.Error(w, "session already attached", http.StatusConflict)
		return true
	}
	s.attached = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.attached = false
		s.mu.Unlock()
	}()

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	defer c.CloseNow()
	c.SetReadLimit(term.MaxInputBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Reconnect: the session outlived its device connection. Dial again before
	// the operator sees a terminal, so a failed redial is an error on the socket
	// rather than a window that opens onto nothing.
	s.mu.Lock()
	need := s.conn == nil && !s.closed
	s.mu.Unlock()
	if need {
		if err := g.dial(ctx, s); err != nil {
			// Tell the console it may try again — a device that refused one dial
			// (vty pool full, still rebooting) commonly accepts the next.
			_ = c.Close(term.CloseDeviceGone, "could not reach the device")
			return true
		}
		if g.deps.Events != nil {
			// Recorded as an event, not written into the transcript: the transcript
			// is what the device printed, and our own commentary does not belong
			// in evidence. A reviewer sees the gap and this event explains it.
			_ = g.deps.Events.RecordEvent(ctx, s.id, "telnet_reconnect", map[string]any{"host": s.deviceLabel})
		}
	}

	if err := g.pump(ctx, c, s); err != nil && !isSessionOver(err) {
		// The device connection is gone while the session itself is still good.
		// Drop it so the next attach redials, and tell the console which of the
		// two silences this is — it cannot tell them apart on its own.
		g.dropConn(s)
		_ = c.Close(term.CloseDeviceGone, "device connection lost")
		return true
	}
	// A clean end: the device hung up, or the session was torn down. Both mean
	// there is nothing to reconnect to right now.
	g.dropConn(s)
	_ = c.Close(websocket.StatusNormalClosure, "")
	return true
}

// dropConn closes the device connection but keeps the session, so a reconnect
// can dial again. It does NOT finalize the recording: the session is still open
// and its transcript is still accumulating.
func (g *Gateway) dropConn(s *telnetSession) {
	s.mu.Lock()
	c := s.conn
	s.conn = nil
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// pump wires the device to the socket until either end closes.
func (g *Gateway) pump(ctx context.Context, ws *websocket.Conn, s *telnetSession) error {
	s.mu.Lock()
	dev := s.conn
	banner := s.banner
	s.mu.Unlock()
	if dev == nil {
		return io.EOF
	}

	// Replay the login so the operator sees how they got in. Already in the
	// transcript from the dial, so this is not recorded again — writing it twice
	// would put the banner in the evidence twice.
	if len(banner) > 0 {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := ws.Write(wctx, websocket.MessageBinary, banner)
		cancel()
		if err != nil {
			return err
		}
	}

	if g.deps.Events != nil {
		_ = g.deps.Events.RecordEvent(ctx, s.id, "telnet_open", map[string]any{"host": s.deviceLabel})
	}

	errc := make(chan error, 2)

	// Device -> operator.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := dev.Read(buf)
			if n > 0 {
				g.emit(ctx, ws, s, buf[:n])
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// Operator -> device.
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			if err := g.dispatch(dev, s, data); err != nil {
				errc <- err
				return
			}
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// dispatch applies one client message.
func (g *Gateway) dispatch(dev *conn, s *telnetSession, data []byte) error {
	m, ok := term.ParseClientMsg(data)
	if !ok {
		return nil // ignore malformed frames rather than killing the session
	}
	switch m.T {
	case term.MsgInput:
		// Typing is what proves an operator is still there. A resize is not: a
		// window manager can emit one with nobody at the keyboard, so counting it
		// as activity would keep an abandoned session alive past its idle timeout.
		g.touch(s)
		_, err := dev.Write([]byte(m.D))
		return err
	case term.MsgResize:
		if m.Cols <= 0 || m.Rows <= 0 {
			return nil
		}
		if s.rec != nil {
			s.rec.Resize(m.Cols, m.Rows)
		}
		return dev.Resize(m.Cols, m.Rows)
	}
	return nil
}

// emit sends device output to the operator and to the transcript.
func (g *Gateway) emit(ctx context.Context, ws *websocket.Conn, s *telnetSession, b []byte) {
	if s.rec != nil {
		s.rec.Write(b)
	}
	// Bound the write so a browser that has stopped reading cannot wedge the
	// reader goroutine and, with it, the device session.
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = ws.Write(wctx, websocket.MessageBinary, b)
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
