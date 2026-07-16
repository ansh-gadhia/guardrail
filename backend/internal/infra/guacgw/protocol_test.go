package guacgw

import (
	"io"
	"strings"
	"testing"
)

// The wire format is LENGTH.VALUE with the length counted in CODE POINTS, and
// with no escaping of any kind. Both facts are easy to get subtly wrong, and both
// failure modes land on credentials — the one payload a PAM must never mangle. So
// each is pinned here rather than trusted.

func TestEncodeSimpleInstruction(t *testing.T) {
	got := Instruction{Opcode: "select", Args: []string{"vnc"}}.String()
	if want := "6.select,3.vnc;"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncodeNoArgs(t *testing.T) {
	if got, want := (Instruction{Opcode: "nop"}).String(), "3.nop;"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The length is code points, not bytes. Encoding len(s) would send a length
// guacd disagrees with the moment a password carries a non-ASCII character, and
// the connection dies in the handshake with nothing useful in the log.
func TestEncodeCountsCodePointsNotBytes(t *testing.T) {
	// "é" is 2 bytes, 1 code point. "日本" is 6 bytes, 2 code points.
	got := Instruction{Opcode: "connect", Args: []string{"é", "日本"}}.String()
	if want := "7.connect,1.é,2.日本;"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Round-tripping is the property that matters: whatever goes in comes back out
// byte-identical, including the characters that look like protocol syntax.
func TestRoundTripPreservesDelimitersInsideValues(t *testing.T) {
	// A password of exactly this shape is legal, and every character in it is a
	// protocol delimiter. Splitting the stream on ';' or ',' would corrupt it and
	// desync every instruction after it.
	nasty := []string{"pa;ss,word.1", ";", ",", "4.fake", ""}
	in := Instruction{Opcode: "connect", Args: nasty}

	got, err := newReader(strings.NewReader(in.String())).ReadInstruction()
	if err != nil {
		t.Fatalf("ReadInstruction: %v", err)
	}
	if got.Opcode != "connect" {
		t.Errorf("opcode = %q, want %q", got.Opcode, "connect")
	}
	if len(got.Args) != len(nasty) {
		t.Fatalf("got %d args, want %d: %q", len(got.Args), len(nasty), got.Args)
	}
	for i := range nasty {
		if got.Args[i] != nasty[i] {
			t.Errorf("arg %d = %q, want %q", i, got.Args[i], nasty[i])
		}
	}
}

func TestRoundTripUnicode(t *testing.T) {
	in := Instruction{Opcode: "key", Args: []string{"日本語", "é", "🔒"}}
	got, err := newReader(strings.NewReader(in.String())).ReadInstruction()
	if err != nil {
		t.Fatalf("ReadInstruction: %v", err)
	}
	for i, want := range in.Args {
		if got.Arg(i) != want {
			t.Errorf("arg %d = %q, want %q", i, got.Arg(i), want)
		}
	}
}

func TestReadsInstructionsInSequence(t *testing.T) {
	stream := Instruction{Opcode: "args", Args: []string{"hostname", "port"}}.String() +
		Instruction{Opcode: "ready", Args: []string{"$260"}}.String()
	r := newReader(strings.NewReader(stream))

	first, err := r.ReadInstruction()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.Opcode != "args" || first.Arg(1) != "port" {
		t.Errorf("first = %+v", first)
	}
	second, err := r.ReadInstruction()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.Opcode != "ready" || second.Arg(0) != "$260" {
		t.Errorf("second = %+v", second)
	}
	if _, err := r.ReadInstruction(); err != io.EOF {
		t.Errorf("after the stream, err = %v, want io.EOF", err)
	}
}

// Arg is read positionally from guacd's replies. A short reply must yield "" and
// not panic — this runs on whatever the daemon sends.
func TestArgOutOfRangeIsEmpty(t *testing.T) {
	in := Instruction{Opcode: "ready", Args: []string{"$260"}}
	for _, n := range []int{-1, 1, 99} {
		if got := in.Arg(n); got != "" {
			t.Errorf("Arg(%d) = %q, want empty", n, got)
		}
	}
}

// Malformed input must be an error, never a panic or a silent truncation: this
// parser reads from a network daemon.
func TestMalformedInputIsRejected(t *testing.T) {
	cases := map[string]string{
		"non-numeric length": "x.foo;",
		"bad separator":      "3.foo|3.bar;",
		"length overruns":    "9.ab;",
		"no terminator":      "3.foo",
		"empty":              "",
		"absurd length":      "99999999999.a;",
	}
	for name, s := range cases {
		if _, err := newReader(strings.NewReader(s)).ReadInstruction(); err == nil {
			t.Errorf("%s: %q parsed without error", name, s)
		}
	}
}

// A value longer than the cap must be refused rather than allocated: the length
// prefix is attacker-supplied.
func TestOversizedElementIsRefused(t *testing.T) {
	_, err := newReader(strings.NewReader("1048577.x;")).ReadInstruction()
	if err == nil {
		t.Fatal("an element over the cap was accepted")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("err = %v, want it to name the range check", err)
	}
}

// An EMPTY opcode is legal and load-bearing: guacamole-common-js uses it for
// messages between the client and the tunnel, the keepalive ping among them.
//
// The parser originally decided "is the opcode slot free?" by testing whether it
// was still the empty string, which cannot tell "no opcode yet" from "the opcode
// is empty". The ping's first argument was promoted to opcode, the tunnel stopped
// recognising its own protocol, and static desktops timed out after 15 seconds.
func TestReadInstructionKeepsAnEmptyOpcodeEmpty(t *testing.T) {
	ping := Instruction{Opcode: "", Args: []string{"ping", "1752579000000"}}

	got, err := newReader(strings.NewReader(ping.String())).ReadInstruction()
	if err != nil {
		t.Fatalf("parsing %q: %v", ping.String(), err)
	}
	if got.Opcode != "" {
		t.Errorf("opcode = %q, want empty — an argument was promoted to opcode", got.Opcode)
	}
	if len(got.Args) != 2 || got.Arg(0) != "ping" || got.Arg(1) != "1752579000000" {
		t.Errorf("args = %v, want [ping 1752579000000]", got.Args)
	}
}

// The same shape, round-tripped: encode -> decode must be identity, empty opcode
// and empty arguments included.
func TestInstructionRoundTripsEmptyElements(t *testing.T) {
	for _, want := range []Instruction{
		{Opcode: "", Args: []string{"ping", "1"}},
		{Opcode: "connect", Args: []string{"", "", "x"}},
		{Opcode: "nop"},
		{Opcode: "", Args: []string{""}},
	} {
		got, err := newReader(strings.NewReader(want.String())).ReadInstruction()
		if err != nil {
			t.Fatalf("parsing %q: %v", want.String(), err)
		}
		if got.Opcode != want.Opcode || len(got.Args) != len(want.Args) {
			t.Errorf("round-trip of %q gave %q %v, want %q %v",
				want.String(), got.Opcode, got.Args, want.Opcode, want.Args)
			continue
		}
		for i := range want.Args {
			if got.Arg(i) != want.Arg(i) {
				t.Errorf("round-trip of %q: arg %d = %q, want %q", want.String(), i, got.Arg(i), want.Arg(i))
			}
		}
	}
}
