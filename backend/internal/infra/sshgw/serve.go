package sshgw

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

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
		Protocol:  "SSH",
	})))
	return true
}

// Stream bridges the operator's WebSocket to the device's PTY.
func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}

	// One terminal per session. Without this a second tab would attach to the same
	// PTY, interleaving two people's keystrokes into one transcript that
	// attributes everything to whoever opened the session.
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

	// Same-origin is enforced by the session cookie/token, matching the browser
	// gateway.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	defer c.CloseNow()
	// Terminal output is unbounded in time; the socket lives as long as the shell.
	c.SetReadLimit(term.MaxInputBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if err := g.pump(ctx, c, s); err != nil && !isNormalClose(err) {
		// The device connection is gone while the session itself is still good.
		// Say so with the code the console reads as "offer a reconnect", rather
		// than the old generic error that left a terminal which had silently
		// stopped responding and no way to act on it.
		_ = c.Close(term.CloseDeviceGone, "device connection lost")
		return true
	}
	// A clean end — the shell exited, or the session was torn down. There is
	// nothing to reconnect to, and the console must not pretend otherwise.
	_ = c.Close(websocket.StatusNormalClosure, "")
	return true
}

// pump wires the PTY to the socket until either end closes.
func (g *Gateway) pump(ctx context.Context, c *websocket.Conn, s *sshSession) error {
	// Redials if the device connection died since the last viewer. This is the
	// reconnect path: the console's Reconnect button is just a new WebSocket.
	sess, err := g.deviceSession(ctx, s)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	// Merge stderr into the same stream: a terminal shows both interleaved, and
	// splitting them would misrepresent the order things appeared on screen.
	sess.Stderr = writerFunc(func(b []byte) (int, error) {
		g.emit(ctx, c, s, b)
		return len(b), nil
	})

	// A real PTY, so full-screen tools (vi, top) and job control behave. xterm
	// matches what the console renders.
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		return err
	}
	if err := sess.Shell(); err != nil {
		return err
	}

	if g.deps.Events != nil {
		_ = g.deps.Events.RecordEvent(ctx, s.id, "ssh_open", map[string]any{"host": s.deviceLabel})
	}

	errc := make(chan error, 2)

	// Device -> operator.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				g.emit(ctx, c, s, buf[:n])
			}
			if rerr != nil {
				errc <- rerr
				return
			}
		}
	}()

	// Operator -> device.
	go func() {
		for {
			typ, data, rerr := c.Read(ctx)
			if rerr != nil {
				errc <- rerr
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			if werr := g.dispatch(sess, stdin, s, data); werr != nil {
				errc <- werr
				return
			}
		}
	}()

	// Whichever side ends first ends the session.
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// dispatch applies one client message.
func (g *Gateway) dispatch(sess *ssh.Session, stdin io.Writer, s *sshSession, data []byte) error {
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
		_, err := stdin.Write([]byte(m.D))
		return err
	case term.MsgResize:
		if m.Cols <= 0 || m.Rows <= 0 {
			return nil
		}
		if s.rec != nil {
			s.rec.Resize(m.Cols, m.Rows)
		}
		return sess.WindowChange(m.Rows, m.Cols)
	}
	return nil
}

// emit sends device output to the operator and to the transcript.
func (g *Gateway) emit(ctx context.Context, c *websocket.Conn, s *sshSession, b []byte) {
	if s.rec != nil {
		s.rec.Write(b)
	}
	// Bound the write so a browser that has stopped reading cannot wedge the
	// reader goroutine and, with it, the device session.
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = c.Write(wctx, websocket.MessageBinary, b)
}

// touch marks the session as in use for the idle reaper.
func (g *Gateway) touch(s *sshSession) {
	if g.deps.Activity != nil {
		g.deps.Activity.Touch(s.id)
	}
}

// isNormalClose reports whether an error is just the far end hanging up.
func isNormalClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	// A shell exiting closes the channel; that is the session ending normally.
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return true
	}
	var missing *ssh.ExitMissingError
	return errors.As(err, &missing)
}

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
