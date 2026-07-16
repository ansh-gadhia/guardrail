// Package guacgw brokers RDP and VNC sessions through guacd, the Apache
// Guacamole proxy daemon.
//
// guacd does the protocol work — it speaks RDP/VNC to the device and renders the
// result into a stream of drawing instructions — and GuardRail sits between it
// and the operator's browser. That placement is the whole point: the device
// credential is handed to guacd inside the connect handshake, server-side, and
// the browser only ever receives drawing instructions. An operator gets a desktop
// they never hold a password for, which is the same guarantee browser isolation
// gives a web UI and the reverse proxy cannot.
package guacgw

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The Guacamole protocol is a stream of instructions:
//
//	5.error,3.foo,1.0;
//
// Each element is LENGTH.VALUE, comma-separated, terminated by a semicolon. The
// length is a count of UNICODE CODE POINTS, not bytes — which is the detail that
// makes hand-rolling this wrong: a password with an accent in it, or a device
// name in Cyrillic, silently produces a length guacd disagrees with, and the
// connection dies at the handshake with no useful error.
//
// The maximum length of a single instruction guacd will accept. Reading is
// bounded by it so a hostile or broken peer cannot make GuardRail allocate
// without limit.
const maxInstructionBytes = 1 << 20 // 1 MiB

// Instruction is one protocol instruction: an opcode and its arguments.
type Instruction struct {
	Opcode string
	Args   []string
}

// String encodes the instruction in wire form.
//
// Lengths are counted in code points via utf8-aware conversion, matching guacd's
// own parser. Encoding it as len(s) would be right only for ASCII and wrong for
// exactly the inputs a PAM cannot afford to be wrong about — credentials.
func (i Instruction) String() string {
	var b strings.Builder
	writeElem(&b, i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		writeElem(&b, a)
	}
	b.WriteByte(';')
	return b.String()
}

func writeElem(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len([]rune(s))))
	b.WriteByte('.')
	b.WriteString(s)
}

// Arg returns the nth argument, or "" when there is no such argument. Callers
// read guacd's replies positionally, and a short reply must not panic.
func (i Instruction) Arg(n int) string {
	if n < 0 || n >= len(i.Args) {
		return ""
	}
	return i.Args[n]
}

// reader decodes instructions from a stream.
type reader struct {
	br *bufio.Reader
}

func newReader(r io.Reader) *reader {
	return &reader{br: bufio.NewReaderSize(r, 16<<10)}
}

// Buffered reports how many bytes are already read and waiting. Used by the relay
// to batch: while this is non-zero, more complete instructions can be decoded
// without another syscall, so they can travel in one WebSocket message.
func (r *reader) Buffered() int { return r.br.Buffered() }

// Peek reports whether at least n bytes can be had WITHOUT consuming them, so it
// can be used to test liveness without stealing from the stream.
func (r *reader) Peek(n int) ([]byte, error) { return r.br.Peek(n) }

// ReadInstruction decodes the next instruction.
//
// It parses element by element rather than reading up to the next ';', because a
// ';' is perfectly legal INSIDE an element's value — an RDP password of "a;b" is
// not a terminator, and splitting on it would corrupt the credential and desync
// the stream for every instruction after it.
func (r *reader) ReadInstruction() (Instruction, error) {
	var in Instruction
	// Position decides what an element is, NOT its value. Testing `in.Opcode == ""`
	// to mean "the opcode slot is still free" cannot represent an EMPTY opcode —
	// and the empty opcode is real: it is what guacamole-common-js reserves for
	// messages between the client and the tunnel. Parsing the client's keepalive
	// `0.,4.ping,13.<ts>;` that way promoted "ping" to the opcode, so the tunnel saw
	// an ordinary instruction, forwarded the keepalive to guacd, and answered
	// nothing — leaving every static desktop to time out after 15 seconds.
	first := true
	for {
		elem, last, err := r.readElement()
		if err != nil {
			return Instruction{}, err
		}
		if first {
			in.Opcode = elem
			first = false
		} else {
			in.Args = append(in.Args, elem)
		}
		if last {
			return in, nil
		}
	}
}

// readElement reads one LENGTH.VALUE element, reporting whether it ended the
// instruction (';' rather than ',').
func (r *reader) readElement() (string, bool, error) {
	// Length prefix, up to the '.'.
	var digits strings.Builder
	for {
		c, err := r.br.ReadByte()
		if err != nil {
			return "", false, err
		}
		if c == '.' {
			break
		}
		if c < '0' || c > '9' {
			return "", false, fmt.Errorf("guac: bad length prefix byte %q", c)
		}
		digits.WriteByte(c)
		if digits.Len() > 10 {
			return "", false, fmt.Errorf("guac: length prefix too long")
		}
	}
	n, err := strconv.Atoi(digits.String())
	if err != nil {
		return "", false, fmt.Errorf("guac: bad length: %w", err)
	}
	if n < 0 || n > maxInstructionBytes {
		return "", false, fmt.Errorf("guac: element length %d out of range", n)
	}

	// n is code points, so read runes rather than bytes.
	runes := make([]rune, 0, n)
	for len(runes) < n {
		ch, _, err := r.br.ReadRune()
		if err != nil {
			return "", false, err
		}
		runes = append(runes, ch)
	}

	sep, err := r.br.ReadByte()
	if err != nil {
		return "", false, err
	}
	switch sep {
	case ',':
		return string(runes), false, nil
	case ';':
		return string(runes), true, nil
	default:
		return "", false, fmt.Errorf("guac: bad separator %q after element", sep)
	}
}
