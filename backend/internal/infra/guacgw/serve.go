package guacgw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// maxClientBytes bounds one message from the browser. Guacamole client messages
// are key, mouse and clipboard events; anything larger is not a person using a
// desktop.
const maxClientBytes = 1 << 20

// maxBatchBytes caps how much decoded output is coalesced into one WebSocket
// message before flushing. Purely a throughput/latency trade: bigger batches mean
// fewer frames on the wire, smaller ones mean the desktop repaints sooner.
const maxBatchBytes = 64 << 10

// Console declines: a desktop session has no page to serve.
//
// The other gateways answer /proxy/<sid>/ with something to render — the device's
// own HTML, or a viewer. A desktop is drawn by the console app itself, which
// decodes the instruction stream onto a canvas and opens the socket below
// directly, so there is nothing to navigate to. Returning false lets the mux fall
// through rather than answering with a blank page that looks like a bug.
func (g *Gateway) Console(http.ResponseWriter, *http.Request, uuid.UUID, string, string) bool {
	return false
}

// Stream bridges the operator's WebSocket to guacd.
//
// The relay is deliberately dumb: instructions pass through in both directions
// without interpretation. GuardRail has already done its work by this point — the
// credential went into the handshake, server-side, and what flows here is drawing
// instructions and input events. Parsing them would add a place to get it wrong
// and buy nothing.
func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	s := g.lookup(sid, token)
	if s == nil {
		return false
	}

	// One viewer per session. Without this a second tab would attach to the same
	// guacd connection, interleaving two people's input into one recording that
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

	// Same-origin is enforced by the session cookie/token, matching the other
	// gateways.
	//
	// Subprotocols is NOT optional here. guacamole-common-js opens the tunnel with
	// `new WebSocket(url, "guacamole")`, and the WebSocket spec requires a client
	// to FAIL the connection when the server's handshake does not select one of the
	// subprotocols it offered. Omitting it produced a 101 in our access log and an
	// immediate disconnect in the browser — the server believed it had accepted a
	// connection the browser had already thrown away.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{"guacamole"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return true // the handshake already responded
	}
	c.SetReadLimit(maxClientBytes)
	defer c.CloseNow()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if g.deps.Events != nil {
		_ = g.deps.Events.RecordEvent(ctx, s.id, "desktop_open", map[string]any{
			"host": s.deviceLabel, "protocol": string(g.proto),
		})
	}

	done := make(chan struct{}, 2)

	// guacd -> browser.
	//
	// Framed on instruction boundaries, NOT relayed as raw chunks. The client
	// parses each WebSocket message as a whole number of complete instructions and
	// does not buffer across messages: a message ending mid-instruction makes it
	// close the tunnel with "Incomplete instruction." Raw 32KB reads split a large
	// `img`/`blob` in the middle as a matter of course, so the old code was a
	// desktop that died as soon as one frame exceeded the buffer.
	//
	// It also reads through s.conn.r — the same buffered reader the handshake used.
	// Reading the net.Conn directly bypassed it and silently discarded whatever
	// guacd had already sent that was sitting in the buffer, which is the opening
	// frame more often than not.
	go func() {
		defer func() { done <- struct{}{} }()
		batch := make([]byte, 0, 32<<10)
		for {
			in, err := s.conn.r.ReadInstruction()
			if err != nil {
				return
			}
			batch = append(batch, in.String()...)
			// Coalesce whatever is already decoded into one message, then flush.
			// One message per instruction would be correct but wasteful: a painting
			// desktop emits img/blob/end triples continuously.
			if s.conn.r.Buffered() == 0 || len(batch) >= maxBatchBytes {
				if err := c.Write(ctx, websocket.MessageText, batch); err != nil {
					return
				}
				batch = batch[:0]
			}
		}
	}()

	// browser -> guacd.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			forward, ping, err := splitClientMessage(data)
			if err != nil {
				return // the client sent something unparseable; do not pass it to guacd
			}
			// Answer the tunnel's keepalive ourselves. The client pings on a timer and
			// closes the tunnel after receiveTimeout (15s) without ANY message, so a
			// desktop showing a static screen — nobody typing, nothing redrawing —
			// dies on its own without this. guacd does not speak the tunnel's internal
			// opcodes, so forwarding the ping there answers nothing and puts a
			// meaningless instruction into the device stream.
			if len(ping) > 0 {
				if err := c.Write(ctx, websocket.MessageText, ping); err != nil {
					return
				}
			}
			if len(forward) == 0 {
				// A ping is not input. Touching activity here would keep an abandoned,
				// logged-in desktop alive forever on its own keepalives, which is
				// precisely what the idle timeout exists to prevent.
				continue
			}
			// Input is what proves a session is in use. Marked on input only: the
			// device redraws a clock on its own, and counting that as activity would
			// keep an abandoned, logged-in desktop alive indefinitely — which is the
			// exact thing the idle timeout exists to close.
			if g.deps.Activity != nil {
				g.deps.Activity.Touch(s.id)
			}
			if _, err := s.conn.Write(forward); err != nil {
				return
			}
		}
	}()

	<-done
	cancel()

	// The viewer closing is not the session ending: the operator may reconnect,
	// and the broker owns the session's lifecycle. Only tear guacd down when the
	// connection itself is gone, which the read loop reports by returning.
	if err := s.conn.SetReadDeadline(time.Now()); err != nil {
		return true
	}
	// Peek, not Read: Read CONSUMES. If guacd had a byte waiting — which is likely,
	// since it keeps painting after the viewer goes away — this probe would swallow
	// it and the next viewer would resume mid-instruction against a stream that no
	// longer parses. Peek answers the same question and puts nothing at risk.
	_, err = s.conn.r.Peek(1)
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		// guacd hung up: the desktop is gone, so release it rather than leave a
		// dead session holding a slot.
		_ = g.End(context.WithoutCancel(ctx), s.id)
	} else {
		// Still alive — restore the blocking read for the next viewer.
		_ = s.conn.SetReadDeadline(time.Time{})
	}
	return true
}

// internalOpcode is the tunnel's own opcode: the empty string. guacamole-common-js
// reserves it for messages between the client and the TUNNEL — never the device —
// and guacd knows nothing about it.
const internalOpcode = ""

// splitClientMessage separates what belongs to guacd from what belongs to the
// tunnel.
//
// Returns the bytes to forward to guacd, and any replies the tunnel owes the
// client. The client's `ping` is answered here, exactly as guacamole-client's own
// tunnel endpoint does, because the alternative is a keepalive that reaches a
// daemon which cannot answer it — leaving the client to time out at 15s on any
// desktop that is not actively repainting.
func splitClientMessage(data []byte) (forward, replies []byte, err error) {
	r := newReader(bytes.NewReader(data))
	for {
		in, rerr := r.ReadInstruction()
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return forward, replies, nil
			}
			return nil, nil, rerr
		}
		if in.Opcode != internalOpcode {
			forward = append(forward, in.String()...)
			continue
		}
		// "ping" is the only internal message a client sends. The reply is the same
		// instruction back — the client matches it against what it sent.
		if in.Arg(0) == "ping" {
			replies = append(replies, Instruction{
				Opcode: internalOpcode, Args: []string{"ping", in.Arg(1)},
			}.String()...)
		}
		// Anything else internal is silently dropped rather than forwarded: guacd has
		// no meaning for it.
	}
}
