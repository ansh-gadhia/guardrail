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
		Protocol:  "SSH",
	})))
	return true
}

// operatorQueue is how many chunks of output the operator's window may fall
// behind by before it is caught up from the scrollback instead.
const operatorQueue = 256

// Stream attaches the operator's WebSocket to the session's shell.
//
// The shell is the session's, opened by the first window and kept until the
// session ends (see sshSession.shell). This only attaches to it: the screen as
// it stands first, from the scrollback, then live output; and on the way out it
// only detaches. Leaving the page and coming back is a reattach, not a new login.
func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}
	if s.isClosed() {
		http.Error(w, "session is over", http.StatusGone)
		return true
	}

	// Same-origin is enforced by the session cookie/token, matching the browser
	// gateway.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	// Errors closing a socket that is already going away are not actionable.
	defer func() { _ = c.CloseNow() }()
	// Terminal output is unbounded in time; the socket lives as long as the shell.
	c.SetReadLimit(term.MaxInputBytes)

	// Two contexts, because cancelling one that a Read is waiting on makes the
	// websocket library drop the connection on the spot. ctx carries the socket's
	// reads and writes and lives as long as this handler; view is what a newer
	// window cancels to take the keyboard, and it is only ever waited on — so the
	// window being replaced can still be sent the close that says why.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	view, viewCancel := context.WithCancel(ctx)
	defer viewCancel()
	// One keyboard per session: this window takes it, and whichever had it is
	// closed with CloseTakenOver (see takeOver).
	gen := s.takeOver(viewCancel)
	defer s.release(gen)
	// Pinged, so a reverse proxy does not cut the socket for being quiet. See
	// term.KeepAlive.
	go term.KeepAlive(ctx, c, term.KeepAliveInterval)

	done, err := g.ensureShell(ctx, s)
	if err != nil {
		// The device could not be reached or refused us while the session itself
		// is still good: the code the console reads as "offer a reconnect".
		_ = c.Close(term.CloseDeviceGone, "could not reach the device")
		return true
	}

	ob, screen := s.op.AttachQueue(operatorQueue)
	defer s.op.Detach(ob)
	// The screen as it stands, before anything new. Escape sequences included, so
	// colours, the cursor and full-screen programs come back as they were.
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
				// This window fell too far behind the device. What it shows is no
				// longer the screen; reattaching brings it up to date from the
				// scrollback, and the console reconnects on this code by itself.
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
			// Whatever the shell printed last is still queued; show it before
			// saying it has gone.
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
			if s.isClosed() || s.endedCleanly() {
				// The shell exited, or the session was torn down: nothing to
				// reconnect to, and the console must not pretend otherwise.
				_ = c.Close(websocket.StatusNormalClosure, "")
			} else {
				_ = c.Close(term.CloseDeviceGone, "device connection lost")
			}
			return true
		case <-left:
			// The window went away. The shell does not: it carries on for the
			// session, recorded and watchable, for the next window to attach to.
			return true
		case <-view.Done():
			if s.superseded(gen) {
				_ = c.Close(term.CloseTakenOver, "opened in another window")
			}
			return true
		}
	}
}

// ensureShell returns the session's shell, opening one if it has none — the
// first window, or the first after the device dropped the last one. done closes
// when that shell's output ends.
func (g *Gateway) ensureShell(ctx context.Context, s *sshSession) (<-chan struct{}, error) {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()

	s.mu.Lock()
	done := s.shellDone
	s.mu.Unlock()
	if done != nil {
		select {
		case <-done: // ended; open another below
		default:
			return done, nil
		}
	}

	// Redials if the device connection died since the last shell.
	sess, err := g.deviceSession(ctx, s)
	if err != nil {
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	// Merge stderr into the same stream: a terminal shows both interleaved, and
	// splitting them would misrepresent the order things appeared on screen.
	sess.Stderr = writerFunc(func(b []byte) (int, error) {
		g.output(s, b)
		return len(b), nil
	})

	s.mu.Lock()
	cols, rows := s.cols, s.rows
	s.mu.Unlock()
	if cols <= 0 || rows <= 0 {
		cols, rows = 80, 24
	}
	// A real PTY, so full-screen tools (vi, top) and job control behave. xterm
	// matches what the console renders.
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, err
	}

	done = make(chan struct{})
	s.mu.Lock()
	s.shell, s.stdin, s.shellDone, s.shellErr = sess, stdin, done, nil
	s.mu.Unlock()
	if g.deps.Events != nil {
		_ = g.deps.Events.RecordEvent(ctx, s.id, "ssh_open", map[string]any{"host": s.deviceLabel})
	}
	go g.readShell(s, sess, stdout, done)
	return done, nil
}

// readShell copies the shell's output to everyone who gets it, until it ends.
func (g *Gateway) readShell(s *sshSession, sess *ssh.Session, stdout io.Reader, done chan struct{}) {
	buf := make([]byte, 32<<10)
	var err error
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 {
			g.output(s, buf[:n])
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	// EOF is what both an exiting shell and a dropped connection look like from
	// here; the channel's exit status tells them apart.
	if errors.Is(err, io.EOF) {
		err = sess.Wait()
	}
	_ = sess.Close()
	s.mu.Lock()
	s.shellErr = err
	s.stdin = nil
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		// The shell went while the session lives on: the operator exited it, or
		// the device dropped the connection. The timeline says which, because a
		// gap before a reconnect reads very differently in each case.
		s.activity.Record("shell_end", shellEnd(err))
	}
	close(done)
}

// shellEnd describes how a shell ended, for the timeline.
func shellEnd(err error) map[string]any {
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return map[string]any{"how": "exit", "status": 0}
	case errors.As(err, &exit):
		return map[string]any{"how": "exit", "status": exit.ExitStatus()}
	case isNormalClose(err):
		return map[string]any{"how": "exit"}
	default:
		return map[string]any{"how": "lost"}
	}
}

// endedCleanly reports whether the last shell ended by exiting, as opposed to
// losing the device.
func (s *sshSession) endedCleanly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shellErr == nil || isNormalClose(s.shellErr)
}

// dispatch applies one message from the operator's window.
func (g *Gateway) dispatch(s *sshSession, data []byte) {
	m, ok := term.ParseClientMsg(data)
	if !ok {
		return // ignore malformed frames rather than killing the session
	}
	switch m.T {
	case term.MsgInput:
		// Typing is what proves an operator is still there. A resize is not: a
		// window manager can emit one with nobody at the keyboard, so counting it
		// as activity would keep an abandoned session alive past its idle timeout.
		g.touch(s)
		// Before the device sees it, so the command log knows an Enter is coming
		// before the device's answer to it can arrive.
		s.cmds.Input([]byte(m.D))
		s.mu.Lock()
		stdin := s.stdin
		s.mu.Unlock()
		if stdin != nil {
			// A shell that has just ended refuses the write; its end is reported
			// to the window by the done channel, not by this.
			_, _ = stdin.Write([]byte(m.D))
		}
	case term.MsgResize:
		if m.Cols <= 0 || m.Rows <= 0 {
			return
		}
		s.mu.Lock()
		s.cols, s.rows = m.Cols, m.Rows
		shell := s.shell
		s.mu.Unlock()
		if s.rec != nil {
			s.rec.Resize(m.Cols, m.Rows)
		}
		if s.mirror != nil {
			s.mirror.Resize(m.Cols, m.Rows)
		}
		s.cmds.Resize(m.Cols, m.Rows)
		if shell != nil {
			_ = shell.WindowChange(m.Rows, m.Cols)
		}
	}
}

// output sends device output to the transcript, the video, supervisors and the
// operator's window. None of them can hold the shell up: the recorder and mirror
// never block, and a viewer that falls behind is dropped and caught up later.
func (g *Gateway) output(s *sshSession, b []byte) {
	if s.rec != nil {
		s.rec.Write(b)
	}
	if s.mirror != nil {
		s.mirror.Write(b)
	}
	s.cmds.Output(b)
	if s.obs != nil {
		s.obs.Broadcast(b)
	}
	if s.op != nil {
		s.op.Broadcast(b)
	}
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
