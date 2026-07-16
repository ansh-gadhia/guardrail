package guacgw

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// The relay, exercised by a REAL WebSocket client against a REAL guacd stream.
//
// This is the test that was missing, and its absence is why three separate bugs
// shipped: the handshake did not select the "guacamole" subprotocol, the relay cut
// messages at arbitrary 32KB socket reads, and it read past the buffered reader.
// Every one of them is invisible from the server's side — the access log said 101
// and guacd said a user joined — and every one of them made the browser throw the
// socket away. Only a client that behaves like the browser can see any of it.

// streamRig wires a fake guacd to a Gateway and serves Stream over HTTP.
func streamRig(t *testing.T, upstream func(net.Conn)) (url string, sid uuid.UUID, token string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		upstream(c)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	sid, token = uuid.New(), "test-token"
	gw := &Gateway{
		proto:    "rdp",
		cfg:      Config{SessionTTL: time.Minute},
		sessions: map[uuid.UUID]*guacSession{},
	}
	gw.sessions[sid] = &guacSession{
		id:      sid,
		token:   token,
		expires: time.Now().Add(time.Minute),
		conn:    &guacConn{Conn: client, r: newReader(client)},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gw.Stream(w, r, sid, token)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), sid, token
}

// The browser opens the tunnel with `new WebSocket(url, "guacamole")`. The
// WebSocket spec requires it to FAIL the connection when the server's handshake
// selects no subprotocol it offered — so this one field decides whether the
// feature works at all.
func TestStreamNegotiatesTheGuacamoleSubprotocol(t *testing.T) {
	url, _, _ := streamRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte(Instruction{Opcode: "sync", Args: []string{"0"}}.String()))
		select {}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatalf("a client offering the guacamole subprotocol could not connect: %v", err)
	}
	defer c.CloseNow()

	if got := c.Subprotocol(); got != "guacamole" {
		t.Fatalf("server selected subprotocol %q, want \"guacamole\" — every browser drops the tunnel", got)
	}
}

// The client parses each message as a whole number of complete instructions and
// does NOT carry a partial one into the next message: it closes the tunnel with
// "Incomplete instruction." So an instruction far larger than any internal buffer
// must still arrive intact and parseable. A 200KB img blob is an ordinary first
// frame of a desktop.
func TestStreamDeliversAnOversizedInstructionIntact(t *testing.T) {
	huge := strings.Repeat("A", 200<<10)
	url, _, _ := streamRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte(Instruction{Opcode: "blob", Args: []string{"0", huge}}.String()))
		_, _ = c.Write([]byte(Instruction{Opcode: "sync", Args: []string{"1"}}.String()))
		select {}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	c.SetReadLimit(8 << 20)

	// Read messages until the trailing sync arrives, parsing exactly as the browser
	// does: every message must be complete instructions, start to finish.
	var seenBlob, seenSync bool
	for i := 0; i < 20 && !seenSync; i++ {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("stream ended after blob=%v sync=%v: %v", seenBlob, seenSync, err)
		}
		r := newReader(strings.NewReader(string(data)))
		for {
			in, err := r.ReadInstruction()
			if err != nil {
				// A parse failure here IS the browser's "Incomplete instruction."
				if r.Buffered() != 0 || !seenSync {
					break
				}
				break
			}
			switch in.Opcode {
			case "blob":
				if in.Arg(1) != huge {
					t.Fatalf("blob payload corrupted: got %d bytes, want %d", len(in.Arg(1)), len(huge))
				}
				seenBlob = true
			case "sync":
				seenSync = true
			}
		}
	}
	if !seenBlob {
		t.Error("the 200KB instruction never arrived intact; the browser would close the tunnel")
	}
}

// Bytes guacd sent before the viewer attached sit in the buffered reader the
// handshake used. Reading the socket directly skips them, and what gets skipped is
// typically the opening frame — a desktop that stays black.
func TestStreamDeliversBytesBufferedBeforeTheViewerAttached(t *testing.T) {
	url, _, _ := streamRig(t, func(c net.Conn) {
		_, _ = c.Write([]byte(Instruction{Opcode: "size", Args: []string{"0", "1024", "768"}}.String()))
		select {}
	})

	// Give the upstream time to land in the socket before anyone attaches.
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("nothing arrived; the opening frame was dropped: %v", err)
	}
	in, err := newReader(strings.NewReader(string(data))).ReadInstruction()
	if err != nil {
		t.Fatalf("first message is not a parseable instruction: %v", err)
	}
	if in.Opcode != "size" {
		t.Errorf("first instruction is %q, want \"size\" — the opening frame was lost", in.Opcode)
	}
}

// The tunnel's keepalive must be answered by the tunnel, not posted to guacd.
//
// The client pings on a timer and closes the tunnel after receiveTimeout (15s)
// without any message at all. A desktop showing a static screen sends no frames,
// so without an answer here it dies on its own after 15 seconds of somebody simply
// reading what is on screen. guacd cannot answer: the empty opcode is between the
// client and the tunnel, and guacd has never heard of it.
func TestStreamAnswersTunnelPingsWithoutTellingGuacd(t *testing.T) {
	got := make(chan []byte, 4)
	url, _, _ := streamRig(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				got <- b
			}
			if err != nil {
				return
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	// Exactly what guacamole-common-js sends: empty opcode, "ping", timestamp.
	ping := Instruction{Opcode: "", Args: []string{"ping", "1752579000000"}}
	if err := c.Write(ctx, websocket.MessageText, []byte(ping.String())); err != nil {
		t.Fatal(err)
	}

	// The tunnel must answer it.
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("the ping went unanswered; a static desktop would time out after 15s: %v", err)
	}
	in, err := newReader(strings.NewReader(string(data))).ReadInstruction()
	if err != nil {
		t.Fatalf("the ping reply is not a parseable instruction: %v", err)
	}
	if in.Opcode != "" || in.Arg(0) != "ping" || in.Arg(1) != "1752579000000" {
		t.Errorf("ping reply = %q %v, want the same ping back", in.Opcode, in.Args)
	}

	// And guacd must never see it.
	select {
	case b := <-got:
		t.Errorf("the tunnel forwarded %q to guacd; the internal opcode is not part of the device protocol", b)
	case <-time.After(300 * time.Millisecond):
	}
}

// Real input must still reach guacd untouched.
func TestStreamForwardsRealInputToGuacd(t *testing.T) {
	got := make(chan []byte, 4)
	url, _, _ := streamRig(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				got <- b
			}
			if err != nil {
				return
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	key := Instruction{Opcode: "key", Args: []string{"65", "1"}}
	if err := c.Write(ctx, websocket.MessageText, []byte(key.String())); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != key.String() {
			t.Errorf("guacd received %q, want %q", b, key.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the keystroke never reached guacd")
	}
}
