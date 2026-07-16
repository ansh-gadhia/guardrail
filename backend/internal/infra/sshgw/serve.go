package sshgw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// maxInputBytes bounds a single client message. Terminal input is keystrokes and
// the occasional paste; anything larger is not a person typing.
const maxInputBytes = 1 << 20

// Console serves the terminal page for a session.
func (g *Gateway) Console(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token, path string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(consolePage(sid.String(), s.deviceLabel, s.watermark)))
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
	c.SetReadLimit(maxInputBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if err := g.pump(ctx, c, s); err != nil && !isNormalClose(err) {
		// The device connection is gone; tell the operator rather than leaving a
		// terminal that has silently stopped responding.
		_ = c.Close(websocket.StatusInternalError, "session ended")
		return true
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
	return true
}

// pump wires the PTY to the socket until either end closes.
func (g *Gateway) pump(ctx context.Context, c *websocket.Conn, s *sshSession) error {
	sess, err := s.client.NewSession()
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

// clientMsg is one message from the terminal.
type clientMsg struct {
	// T is the type: "i" input, "r" resize.
	T string `json:"t"`
	// D is input data (for "i").
	D string `json:"d,omitempty"`
	// Cols/Rows are the new geometry (for "r").
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
}

// dispatch applies one client message.
func (g *Gateway) dispatch(sess *ssh.Session, stdin io.Writer, s *sshSession, data []byte) error {
	var m clientMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return nil // ignore malformed frames rather than killing the session
	}
	switch m.T {
	case "i":
		// Typing is what proves an operator is still there. A resize is not: a
		// window manager can emit one with nobody at the keyboard, so counting it
		// as activity would keep an abandoned session alive past its idle timeout.
		g.touch(s)
		_, err := stdin.Write([]byte(m.D))
		return err
	case "r":
		if m.Cols <= 0 || m.Rows <= 0 {
			return nil
		}
		if s.rec != nil {
			s.rec.resize(m.Cols, m.Rows)
		}
		return sess.WindowChange(m.Rows, m.Cols)
	}
	return nil
}

// emit sends device output to the operator and to the transcript.
func (g *Gateway) emit(ctx context.Context, c *websocket.Conn, s *sshSession, b []byte) {
	if s.rec != nil {
		s.rec.write(b)
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
