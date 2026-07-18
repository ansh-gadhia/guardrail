package telnetgw

import (
	"bufio"
	"bytes"
	"net"
	"sync"
)

// Telnet commands (RFC 854). Telnet interleaves option negotiation with data on
// one socket, escaping commands behind IAC (0xFF). Everything in this file
// exists to strip that back out, so the rest of the gateway can treat a Cisco
// console exactly like the SSH gateway treats a PTY: as a byte stream.
const (
	cmdSE   = 240 // subnegotiation end
	cmdSB   = 250 // subnegotiation begin
	cmdWILL = 251 // "I will perform this option"
	cmdWONT = 252 // "I will not perform this option"
	cmdDO   = 253 // "please perform this option"
	cmdDONT = 254 // "please stop performing this option"
	cmdIAC  = 255 // Interpret As Command
)

// The options worth negotiating for a management console.
const (
	optEcho     = 1  // RFC 857 — the device echoes what we type
	optSGA      = 3  // RFC 858 — suppress go-ahead, i.e. character-at-a-time
	optTermType = 24 // RFC 1091 — what kind of terminal we are
	optNAWS     = 31 // RFC 1073 — window size
)

// TERMINAL-TYPE subnegotiation verbs (RFC 1091).
const (
	ttIS   = 0
	ttSEND = 1
)

// termType is what we claim to be.
//
// It must match what the shared console actually renders, which is xterm — tell
// a Cisco box "vt100" and it will withhold the sequences xterm can draw; tell it
// something it does not know and some IOS versions fall back to line mode.
const termType = "xterm-256color"

// maxSubBytes bounds one subnegotiation. A device that opens IAC SB and never
// closes it must not grow this buffer without limit.
const maxSubBytes = 256

// Parser states.
const (
	stData = iota
	stIAC
	stWill
	stWont
	stDo
	stDont
	stSub
	stSubIAC
)

// conn presents a telnet connection as a plain byte stream.
//
// Reads return application data with all negotiation stripped; writes escape IAC
// so an operator typing 0xFF cannot forge a command. Negotiation replies are
// written from the read path, so every write takes wmu — a reply racing an
// operator's keystroke would interleave two byte sequences on one socket and
// corrupt both.
type conn struct {
	raw net.Conn
	br  *bufio.Reader

	wmu sync.Mutex // serialises all writes to raw

	state int
	sub   []byte
	out   bytes.Buffer

	// omu guards the negotiated option state and the geometry.
	omu      sync.Mutex
	weWill   map[byte]bool // options we have agreed to perform
	theyWill map[byte]bool // options the far end performs
	cols     int
	rows     int
	nawsOK   bool // the device asked us for window size
}

func newConn(raw net.Conn) *conn {
	return &conn{
		raw:      raw,
		br:       bufio.NewReaderSize(raw, 16<<10),
		weWill:   map[byte]bool{},
		theyWill: map[byte]bool{},
		cols:     80,
		rows:     24,
	}
}

// hello states our opening position rather than waiting to be asked.
//
// Cisco IOS will happily sit in line-at-a-time mode if nobody proposes anything,
// which is what makes a telnet console feel unlike a terminal: no arrow keys, no
// tab completion, a line only arriving on Enter. Asking for remote echo and
// suppress-go-ahead up front is what a real telnet client does and what gets IOS
// into character mode.
func (c *conn) hello() error {
	c.omu.Lock()
	c.weWill[optTermType] = true
	c.weWill[optNAWS] = true
	c.weWill[optSGA] = true
	c.omu.Unlock()
	return c.sendRaw([]byte{
		cmdIAC, cmdWILL, optTermType,
		cmdIAC, cmdWILL, optNAWS,
		cmdIAC, cmdWILL, optSGA,
		cmdIAC, cmdDO, optSGA,
		cmdIAC, cmdDO, optEcho,
	})
}

// Read returns device output with negotiation removed.
func (c *conn) Read(p []byte) (int, error) {
	for {
		if c.out.Len() > 0 {
			return c.out.Read(p)
		}
		// Block for one byte, then drain whatever else already arrived. Without
		// the drain a burst of output would come back a byte at a time, and each
		// byte would become its own WebSocket frame and its own transcript chunk.
		b, err := c.br.ReadByte()
		if err != nil {
			return 0, err
		}
		if err := c.step(b); err != nil {
			return 0, err
		}
		for c.br.Buffered() > 0 {
			b, err := c.br.ReadByte()
			if err != nil {
				break
			}
			if err := c.step(b); err != nil {
				return 0, err
			}
		}
	}
}

// step advances the parser by one byte.
func (c *conn) step(b byte) error {
	switch c.state {
	case stData:
		if b == cmdIAC {
			c.state = stIAC
			return nil
		}
		c.out.WriteByte(b)
	case stIAC:
		switch b {
		case cmdIAC:
			c.out.WriteByte(cmdIAC) // escaped literal 0xFF
			c.state = stData
		case cmdDO:
			c.state = stDo
		case cmdDONT:
			c.state = stDont
		case cmdWILL:
			c.state = stWill
		case cmdWONT:
			c.state = stWont
		case cmdSB:
			c.sub = c.sub[:0]
			c.state = stSub
		default:
			// Two-byte commands (NOP, GA, data mark…). Nothing here acts on them,
			// but they must be consumed or their operand would land in the output.
			c.state = stData
		}
	case stDo:
		c.state = stData
		return c.onDo(b)
	case stDont:
		c.state = stData
		return c.onDont(b)
	case stWill:
		c.state = stData
		return c.onWill(b)
	case stWont:
		c.state = stData
		return c.onWont(b)
	case stSub:
		if b == cmdIAC {
			c.state = stSubIAC
			return nil
		}
		if len(c.sub) < maxSubBytes {
			c.sub = append(c.sub, b)
		}
	case stSubIAC:
		switch b {
		case cmdIAC:
			if len(c.sub) < maxSubBytes {
				c.sub = append(c.sub, cmdIAC)
			}
			c.state = stSub
		case cmdSE:
			c.state = stData
			return c.onSub(c.sub)
		default:
			c.state = stSub
		}
	}
	return nil
}

// weSupport reports the options we are willing to perform.
func weSupport(opt byte) bool {
	return opt == optTermType || opt == optNAWS || opt == optSGA
}

// weWant reports the options we want the device to perform. Echo matters: with
// the device echoing, what appears on the operator's screen is what the device
// actually received, not what our own client guessed.
func weWant(opt byte) bool {
	return opt == optEcho || opt == optSGA
}

// onDo answers "please perform this option".
//
// The guards are not tidiness: RFC 854 requires a party not to acknowledge a
// request for a state it is already in, because two polite implementations that
// always answer will ping-pong the same option forever and never carry data.
func (c *conn) onDo(opt byte) error {
	if !weSupport(opt) {
		// A refusal is always sent, even if repeated: the far end is waiting on an
		// answer, and silence would stall negotiation rather than end it.
		c.omu.Lock()
		c.weWill[opt] = false
		c.omu.Unlock()
		return c.send(cmdWONT, opt)
	}
	c.omu.Lock()
	already := c.weWill[opt]
	c.weWill[opt] = true
	if opt == optNAWS {
		c.nawsOK = true
	}
	c.omu.Unlock()
	if !already {
		if err := c.send(cmdWILL, opt); err != nil {
			return err
		}
	}
	if opt == optNAWS {
		// They asked, so tell them — and keep telling them on every resize.
		return c.sendNAWS()
	}
	return nil
}

func (c *conn) onDont(opt byte) error {
	c.omu.Lock()
	already := !c.weWill[opt]
	c.weWill[opt] = false
	if opt == optNAWS {
		c.nawsOK = false
	}
	c.omu.Unlock()
	if already {
		return nil
	}
	return c.send(cmdWONT, opt)
}

func (c *conn) onWill(opt byte) error {
	if !weWant(opt) {
		c.omu.Lock()
		c.theyWill[opt] = false
		c.omu.Unlock()
		return c.send(cmdDONT, opt)
	}
	c.omu.Lock()
	already := c.theyWill[opt]
	c.theyWill[opt] = true
	c.omu.Unlock()
	if already {
		return nil
	}
	return c.send(cmdDO, opt)
}

func (c *conn) onWont(opt byte) error {
	c.omu.Lock()
	already := !c.theyWill[opt]
	c.theyWill[opt] = false
	c.omu.Unlock()
	if already {
		return nil
	}
	return c.send(cmdDONT, opt)
}

// onSub handles a completed subnegotiation.
func (c *conn) onSub(sub []byte) error {
	if len(sub) < 2 {
		return nil
	}
	if sub[0] == optTermType && sub[1] == ttSEND {
		b := []byte{cmdIAC, cmdSB, optTermType, ttIS}
		b = appendEscaped(b, []byte(termType))
		b = append(b, cmdIAC, cmdSE)
		return c.sendRaw(b)
	}
	return nil
}

// Resize records the console's geometry and tells the device, so full-screen
// output (a `show run` pager, a menu) is laid out for the window the operator
// actually has.
func (c *conn) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	c.omu.Lock()
	c.cols, c.rows = cols, rows
	ok := c.nawsOK
	c.omu.Unlock()
	if !ok {
		return nil // the device never agreed to hear about it
	}
	return c.sendNAWS()
}

// sendNAWS reports the window size (RFC 1073).
func (c *conn) sendNAWS() error {
	c.omu.Lock()
	cols, rows := c.cols, c.rows
	c.omu.Unlock()
	b := []byte{cmdIAC, cmdSB, optNAWS}
	// The size bytes are escaped like any other data: a 255-column window would
	// otherwise emit a bare IAC inside the subnegotiation and desynchronise the
	// device's parser.
	b = appendEscaped(b, []byte{byte(cols >> 8), byte(cols), byte(rows >> 8), byte(rows)})
	b = append(b, cmdIAC, cmdSE)
	return c.sendRaw(b)
}

// Write sends operator input, escaping IAC so a keystroke cannot forge a command.
func (c *conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// IndexByte, not ContainsRune: IAC is the byte 0xFF, and ContainsRune would
	// hunt for the UTF-8 encoding of U+00FF (0xC3 0xBF) and never find it — so
	// the escape below would silently never run.
	if bytes.IndexByte(p, cmdIAC) < 0 {
		c.wmu.Lock()
		defer c.wmu.Unlock()
		return c.raw.Write(p)
	}
	buf := appendEscaped(make([]byte, 0, len(p)+8), p)
	c.wmu.Lock()
	_, err := c.raw.Write(buf)
	c.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	// Report the caller's length, not the escaped one: an io.Writer that claims
	// to have written more bytes than it was given breaks every caller.
	return len(p), nil
}

// send emits one three-byte option command.
func (c *conn) send(cmd, opt byte) error { return c.sendRaw([]byte{cmdIAC, cmd, opt}) }

// sendRaw writes bytes that are already telnet-encoded.
func (c *conn) sendRaw(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.raw.Write(b)
	return err
}

// Close drops the connection.
func (c *conn) Close() error { return c.raw.Close() }

// appendEscaped appends data with IAC doubled.
func appendEscaped(dst, src []byte) []byte {
	for _, b := range src {
		dst = append(dst, b)
		if b == cmdIAC {
			dst = append(dst, cmdIAC)
		}
	}
	return dst
}
