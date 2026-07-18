package telnetgw

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn gives a conn a controllable far end.
//
// A real loopback socket, not net.Pipe: net.Pipe is unbuffered and synchronous,
// so the gateway answering an option mid-read would block on its own write until
// the test read it — deadlocking against the very negotiation under test. A
// device is a socket with kernel buffers, so the fake is one too.
func pipeConn(t *testing.T) (*conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	ours, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	theirs := <-accepted
	if theirs == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	return newConn(ours), theirs
}

// readSoon drains what the far end sent, tolerating the deadline expiring.
// It never fails the test itself: it is called from goroutines, where t.Fatalf
// is not allowed to be.
func readSoon(c net.Conn) []byte {
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4<<10)
	n, _ := c.Read(buf)
	return buf[:n]
}

func TestReadStripsNegotiationFromOutput(t *testing.T) {
	c, far := pipeConn(t)

	// A device that interleaves an option command in the middle of a word. If
	// negotiation leaked into the stream the operator would see mojibake, and the
	// transcript would record it as what the device printed.
	go func() {
		_, _ = far.Write([]byte("Rou"))
		_, _ = far.Write([]byte{cmdIAC, cmdWILL, optEcho})
		_, _ = far.Write([]byte("ter>"))
	}()

	got := make([]byte, 0, 16)
	buf := make([]byte, 64)
	for len(got) < len("Router>") {
		_ = c.raw.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got)
		}
	}
	if string(got) != "Router>" {
		t.Errorf("read = %q, want %q — negotiation leaked into device output", got, "Router>")
	}
}

func TestReadUnescapesADoubledIAC(t *testing.T) {
	c, far := pipeConn(t)
	// 0xFF as literal data is sent doubled. A device printing a 0xFF byte (any
	// binary output, a box-drawing charset) must not be read as a command.
	go func() { _, _ = far.Write([]byte{'a', cmdIAC, cmdIAC, 'b'}) }()

	buf := make([]byte, 16)
	_ = c.raw.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := []byte{'a', 0xFF, 'b'}; !bytes.Equal(buf[:n], want) {
		t.Errorf("read = %v, want %v", buf[:n], want)
	}
}

func TestWriteEscapesIACSoInputCannotForgeACommand(t *testing.T) {
	c, far := pipeConn(t)

	done := make(chan []byte, 1)
	go func() { done <- readSoon(far) }()

	// An operator pasting a 0xFF byte must not be able to inject an option
	// command into the device's parser.
	n, err := c.Write([]byte{'x', 0xFF, 'y'})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// The caller's count, not the escaped one: an io.Writer that reports more
	// bytes than it was handed breaks every caller that loops on short writes.
	if n != 3 {
		t.Errorf("Write returned %d, want 3 (the caller's byte count)", n)
	}
	if got, want := <-done, []byte{'x', cmdIAC, cmdIAC, 'y'}; !bytes.Equal(got, want) {
		t.Errorf("wire = %v, want %v — IAC was not escaped", got, want)
	}
}

func TestHelloAsksForCharacterMode(t *testing.T) {
	c, far := pipeConn(t)
	done := make(chan []byte, 1)
	go func() { done <- readSoon(far) }()

	if err := c.hello(); err != nil {
		t.Fatalf("hello: %v", err)
	}
	got := <-done

	// Remote echo + suppress-go-ahead is what puts IOS into character-at-a-time.
	// Without them a telnet console has no arrow keys and no tab completion, and
	// a line only arrives on Enter — which is the "laggy, unlike SSH" feel.
	for _, want := range [][]byte{
		{cmdIAC, cmdDO, optEcho},
		{cmdIAC, cmdDO, optSGA},
		{cmdIAC, cmdWILL, optTermType},
		{cmdIAC, cmdWILL, optNAWS},
	} {
		if !bytes.Contains(got, want) {
			t.Errorf("hello did not send %v; sent %v", want, got)
		}
	}
}

func TestUnsupportedOptionIsRefused(t *testing.T) {
	c, far := pipeConn(t)
	done := make(chan []byte, 1)
	go func() { done <- readSoon(far) }()

	// Option 42 is nothing we do. Silence would stall the far end waiting on an
	// answer; the protocol requires an explicit refusal.
	go func() { _, _ = far.Write([]byte{cmdIAC, cmdDO, 42}) }()
	buf := make([]byte, 16)
	_ = c.raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Read(buf)

	if got, want := <-done, []byte{cmdIAC, cmdWONT, 42}; !bytes.Contains(got, want) {
		t.Errorf("reply = %v, want it to contain %v", got, want)
	}
}

func TestAgreedOptionIsNotReacknowledged(t *testing.T) {
	c, far := pipeConn(t)

	// Drain hello.
	drained := make(chan struct{})
	go func() { readSoon(far); close(drained) }()
	if err := c.hello(); err != nil {
		t.Fatalf("hello: %v", err)
	}
	<-drained

	// hello already said WILL SGA. Answering DO SGA with another WILL invites the
	// far end to answer again: RFC 854 forbids acknowledging a state you are
	// already in precisely because two polite stacks will loop forever and never
	// carry data.
	replies := make(chan []byte, 1)
	go func() {
		_ = far.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b := make([]byte, 64)
		n, _ := far.Read(b)
		replies <- b[:n]
	}()
	go func() { _, _ = far.Write([]byte{cmdIAC, cmdDO, optSGA}) }()

	buf := make([]byte, 16)
	_ = c.raw.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Read(buf)

	if got := <-replies; bytes.Contains(got, []byte{cmdIAC, cmdWILL, optSGA}) {
		t.Errorf("re-acknowledged an already-agreed option (%v); this is how a negotiation loop starts", got)
	}
}

func TestTerminalTypeSubnegotiationAnswersXterm(t *testing.T) {
	c, far := pipeConn(t)
	done := make(chan []byte, 1)
	go func() { done <- readSoon(far) }()

	go func() {
		_, _ = far.Write([]byte{cmdIAC, cmdSB, optTermType, ttSEND, cmdIAC, cmdSE})
	}()
	buf := make([]byte, 16)
	_ = c.raw.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Read(buf)

	want := append([]byte{cmdIAC, cmdSB, optTermType, ttIS}, []byte(termType)...)
	want = append(want, cmdIAC, cmdSE)
	if got := <-done; !bytes.Contains(got, want) {
		t.Errorf("term type reply = %v, want %v", got, want)
	}
}

func TestResizeIsSilentUntilTheDeviceAsksForNAWS(t *testing.T) {
	c, far := pipeConn(t)

	// Nobody has sent DO NAWS, so a resize has no agreed channel to travel on.
	// Sending one anyway would be an unsolicited subnegotiation.
	sent := make(chan int, 1)
	go func() {
		_ = far.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b := make([]byte, 64)
		n, _ := far.Read(b)
		sent <- n
	}()
	if err := c.Resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if n := <-sent; n != 0 {
		t.Errorf("resize sent %d bytes before the device agreed to NAWS", n)
	}
}

func TestNAWSEscapesAWidthOf255(t *testing.T) {
	c, far := pipeConn(t)

	// 255 columns puts a bare 0xFF inside the subnegotiation. Unescaped, the
	// device reads it as IAC and desynchronises — the terminal then garbles
	// everything after, which is a miserable bug to chase from a symptom.
	c.omu.Lock()
	c.nawsOK = true
	c.omu.Unlock()

	done := make(chan []byte, 1)
	go func() { done <- readSoon(far) }()
	if err := c.Resize(255, 24); err != nil {
		t.Fatalf("resize: %v", err)
	}

	want := []byte{cmdIAC, cmdSB, optNAWS, 0, cmdIAC, cmdIAC, 0, 24, cmdIAC, cmdSE}
	if got := <-done; !bytes.Equal(got, want) {
		t.Errorf("NAWS = %v, want %v", got, want)
	}
}

func TestReadBatchesABurstIntoOneCall(t *testing.T) {
	c, far := pipeConn(t)

	// A byte-at-a-time Read would make every byte its own WebSocket frame and its
	// own transcript chunk — the manifest would balloon and playback would stutter.
	go func() { _, _ = far.Write([]byte("show running-config")) }()

	buf := make([]byte, 256)
	_ = c.raw.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < 2 {
		t.Errorf("read returned %d bytes; a burst should come back in one call, not one byte per call", n)
	}
}
