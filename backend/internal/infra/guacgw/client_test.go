package guacgw

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeGuacd is a guacd that records what it was told and replies on script. It
// exists to pin the one thing that cannot be checked by reading the code: that
// each parameter value lands in the slot guacd asked for.
type fakeGuacd struct {
	// argNames is the parameter list this fake advertises, in order.
	argNames []string
	// failWith, when set, is returned as an `error` instruction instead of `ready`.
	failWith string

	// Captured from the client.
	selected string
	// connectArgs is how many values `connect` carried. Real guacd answers `ready`
	// and then drops the connection when this is short, so counting it here is the
	// only way the fake can catch what the daemon reports minutes later.
	connectArgs int
	got         []Instruction
	// connectByName pairs each advertised parameter with the value received.
	// Keyed by what this fake ACTUALLY advertised, version slot included — pairing
	// argNames against the received values would be off by one and would report
	// every parameter as holding its neighbour's value.
	connectByName map[string]string
}

func (f *fakeGuacd) serve(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f.connectByName = map[string]string{}

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := newReader(c)

		sel, err := r.ReadInstruction()
		if err != nil {
			return
		}
		f.selected = sel.Arg(0)

		// Real guacd lists the version it speaks as the FIRST parameter slot, not as
		// a header — so it is part of the list `connect` must fill, and this fake
		// advertises it the same way.
		advertised := append([]string{"VERSION_1_5_0"}, f.argNames...)
		_, _ = c.Write([]byte(Instruction{Opcode: "args", Args: advertised}.String()))

		// size, audio, video, image, connect
		for i := 0; i < 5; i++ {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			f.got = append(f.got, in)
			if in.Opcode == "connect" {
				f.connectArgs = len(in.Args)
				for j, name := range advertised {
					f.connectByName[name] = in.Arg(j)
				}
			}
		}
		if f.failWith != "" {
			_, _ = c.Write([]byte(Instruction{Opcode: "error", Args: []string{f.failWith, "769"}}.String()))
			return
		}
		_, _ = c.Write([]byte(Instruction{Opcode: "ready", Args: []string{"$fake-conn-id"}}.String()))
		// Hold the connection so the handshake's caller sees a live socket.
		_, _ = r.ReadInstruction()
	}()
	return ln.Addr().String()
}

// The heart of it: `connect` is positional, and the positions are whatever guacd
// just advertised. Values are matched to names, never counted — a hardcoded index
// would send the password into whatever field moved into that slot.
func TestHandshakeSendsValuesInTheOrderGuacdAsked(t *testing.T) {
	// A deliberately hostile order: password first, hostname late, and two names
	// this gateway has never heard of.
	f := &fakeGuacd{argNames: []string{"password", "unknown-a", "port", "username", "hostname", "unknown-b"}}
	addr := f.serve(t)

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{
			"hostname": "10.0.0.5", "port": "5900",
			"username": "operator", "password": "s3cr3t",
		},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	if f.selected != "vnc" {
		t.Errorf("selected %q, want vnc", f.selected)
	}
	// One value per advertised slot — the version included. One short and guacd
	// answers `ready`, then drops the connection with "Client did not return the
	// expected number of arguments": a session that opens and dies a moment later.
	if f.connectArgs != len(f.argNames)+1 {
		t.Errorf("connect carried %d values for %d advertised slots", f.connectArgs, len(f.argNames)+1)
	}
	// The version slot must carry a version, not the first parameter's value.
	if got := f.connectByName["VERSION_1_5_0"]; got != "VERSION_1_5_0" {
		t.Errorf("the version slot received %q; guacd would read the rest one slot out", got)
	}
	want := map[string]string{
		"hostname": "10.0.0.5",
		"port":     "5900",
		"username": "operator",
		"password": "s3cr3t",
		// A parameter this gateway knows nothing about must be sent empty, which
		// guacd reads as "use the default" — not skipped, or every value after it
		// shifts one slot left.
		"unknown-a": "",
		"unknown-b": "",
	}
	for name, w := range want {
		if got := f.connectByName[name]; got != w {
			t.Errorf("guacd received %s=%q, want %q", name, got, w)
		}
	}
	if conn.ID != "$fake-conn-id" {
		t.Errorf("connection id = %q, want the one guacd reported", conn.ID)
	}
}

// The handshake must send exactly the opcodes guacd expects, in order. Missing
// one leaves guacd waiting and the operator staring at a spinner.
func TestHandshakeSendsTheExpectedOpcodes(t *testing.T) {
	f := &fakeGuacd{argNames: []string{"hostname"}}
	addr := f.serve(t)

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "rdp", Width: 1280, Height: 800, DPI: 96,
		Params: map[string]string{"hostname": "h"},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	var opcodes []string
	for _, in := range f.got {
		opcodes = append(opcodes, in.Opcode)
	}
	if strings.Join(opcodes, ",") != "size,audio,video,image,connect" {
		t.Errorf("opcodes = %v, want size,audio,video,image,connect", opcodes)
	}
	// Geometry is what the device is asked to render at.
	if size := f.got[0]; size.Arg(0) != "1280" || size.Arg(1) != "800" || size.Arg(2) != "96" {
		t.Errorf("size = %v, want 1280x800 @96", size.Args)
	}
	// No audio codecs are declared: a device's sound would reach the operator
	// uncaptured by the recording and uncovered by the watermark.
	if audio := f.got[1]; len(audio.Args) != 0 {
		t.Errorf("audio codecs = %v, want none declared", audio.Args)
	}
}

// guacd reports a refused connection as an `error` instruction, not by hanging up.
// Its message is the operator's only clue — wrong password, host unreachable,
// certificate refused — so it must survive to the caller.
func TestHandshakeSurfacesGuacdError(t *testing.T) {
	f := &fakeGuacd{argNames: []string{"hostname"}, failWith: "Connection refused by remote host"}
	addr := f.serve(t)

	_, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc", Params: map[string]string{"hostname": "h"},
	}, 5*time.Second)
	if err == nil {
		t.Fatal("a refused connection returned no error")
	}
	if !strings.Contains(err.Error(), "Connection refused by remote host") {
		t.Errorf("error %q drops guacd's message", err)
	}
}

// A guacd that accepts the TCP connection and then says nothing is what a wedged
// daemon looks like. It must fail the Connect request rather than hang it.
func TestHandshakeTimesOutOnSilentGuacd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Accept and say nothing, holding the connection open.
		defer c.Close()
		time.Sleep(3 * time.Second)
	}()

	start := time.Now()
	_, err = dialGuacd(context.Background(), ln.Addr().String(), connConfig{
		Protocol: "vnc", Params: map[string]string{},
	}, 300*time.Millisecond)
	if err == nil {
		t.Fatal("a silent guacd did not fail the handshake")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v to give up; the handshake timeout is not being applied", elapsed)
	}
}

// An unreachable guacd must name itself in the error. "connection refused" with
// no address sends an operator looking at the wrong service.
func TestHandshakeNamesGuacdWhenUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listens there.
	_, err := dialGuacd(context.Background(), "127.0.0.1:1", connConfig{Protocol: "vnc"}, time.Second)
	if err == nil {
		t.Fatal("dialling a dead address succeeded")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error %q does not name the address it could not reach", err)
	}
}
