package guacgw

import (
	"strings"
	"testing"
)

// The browser opens the tunnel with `new WebSocket(url, "guacamole")`, and the
// WebSocket spec requires it to FAIL the connection if the server's handshake
// does not select a subprotocol the client offered. Accepting without one looked
// entirely healthy from the server's side — a 101 in the access log, a user
// joining in guacd's log — while the browser had already discarded the socket and
// the operator saw "the connection to the session was lost".
//
// It is one field, it has no visible effect on this side, and nothing else here
// would notice its removal. Hence a test.
func TestServeAcceptsTheGuacamoleSubprotocol(t *testing.T) {
	src, err := readSource("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, `Subprotocols:       []string{"guacamole"}`) &&
		!strings.Contains(src, `Subprotocols: []string{"guacamole"}`) {
		t.Error(`the websocket handshake does not select the "guacamole" subprotocol; ` +
			`every browser will drop the tunnel immediately after the 101`)
	}
}

// The client parses each WebSocket message as a whole number of complete
// instructions and does not carry a partial one over to the next message — it
// closes the tunnel with "Incomplete instruction." So the relay must frame on
// instruction boundaries. Relaying raw socket chunks splits a large img/blob as a
// matter of course.
func TestServeRelaysWholeInstructionsFromTheBufferedReader(t *testing.T) {
	src, err := readSource("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, "s.conn.r.ReadInstruction()") {
		t.Error("the guacd->browser relay is not decoding instructions; raw chunks split instructions " +
			"mid-value and the client closes the tunnel")
	}
	// Reading the net.Conn directly anywhere in this file skips the reader the
	// handshake filled: in the relay it throws away whatever guacd already sent, and
	// in the liveness probe it CONSUMES a byte the next viewer needs. Peek is the
	// non-destructive way to ask the same question.
	if strings.Contains(src, "s.conn.Read(") {
		t.Error("something reads the net.Conn directly, bypassing the buffered reader; " +
			"that either discards buffered bytes or steals one from the stream")
	}
}
