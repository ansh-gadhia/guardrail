package term

import (
	"strconv"
	"unicode"
	"unicode/utf8"
)

// screen is a model of the operator's terminal, kept only so the command log
// can read what a line on it says.
//
// The bytes a shell sends are not the line it shows. Readline draws a line and
// then edits it in place: a backspace is "\b \b", a character inserted mid-line
// is a cursor move and an insert-character sequence, a recalled history entry
// is the old line erased and a new one drawn over it, and a line longer than
// the terminal is broken by the terminal itself, not by the shell. The only
// faithful answer to "what command was on that line" is to apply those bytes the
// way the operator's terminal did and read the result — which is what this does.
//
// It implements the subset of xterm that line-oriented programs use — cursor
// movement, erase and insert/delete in a line, scrolling, auto-wrap, and the
// alternate screen full-screen programs switch to — and ignores the rest
// (colour, titles, modes it has no use for). It renders nothing; nobody sees it.
type screen struct {
	cols, rows int
	cells      [][]rune // [row][col]; 0 is blank, wideTail the right half of a wide rune
	wrapped    []bool   // wrapped[y]: row y ran off its right edge onto row y+1
	x, y       int
	wrapNext   bool // the cursor is past the last column; the next character wraps
	autowrap   bool
	insert     bool // insert mode (IRM)
	top, bot   int  // scrolling region, inclusive
	savedX     int
	savedY     int

	// The alternate screen, which full-screen programs (vi, less, top) draw on.
	// What they draw is not a command line, and the shell's screen comes back
	// unchanged when they exit, so the main screen is set aside while it is up.
	alt        bool
	main       [][]rune
	mainWrap   []bool
	mainX      int
	mainY      int
	mainSavedX int
	mainSavedY int

	// Parser state.
	state    int
	params   []byte
	private  byte
	inter    byte
	pending  []byte // an incomplete UTF-8 sequence split across writes
	strEsc   bool   // an ESC seen inside an OSC/DCS string, which may be its terminator
	strBytes int

	// lineFeed is called just before a line feed moves the cursor off its line,
	// while that line still reads as it did.
	lineFeed func()
}

const wideTail = -1

// maxStringBytes bounds an OSC or DCS string. One that never terminates is
// abandoned rather than allowed to swallow the rest of the session.
const maxStringBytes = 4096

const (
	stGround = iota
	stEsc
	stEscInter
	stCSI
	stOSC
	stString // DCS, SOS, PM, APC: skipped to their terminator
)

func newScreen(cols, rows int) *screen {
	s := &screen{autowrap: true}
	s.resize(cols, rows)
	return s
}

func blankGrid(cols, rows int) ([][]rune, []bool) {
	g := make([][]rune, rows)
	for i := range g {
		g[i] = make([]rune, cols)
	}
	return g, make([]bool, rows)
}

// resize changes the geometry, keeping what fits and the cursor's line in view.
func (s *screen) resize(cols, rows int) {
	if cols < 2 {
		cols = 2
	}
	if rows < 1 {
		rows = 1
	}
	if s.cells == nil {
		s.cols, s.rows = cols, rows
		s.cells, s.wrapped = blankGrid(cols, rows)
		s.top, s.bot = 0, rows-1
		return
	}
	s.cells, s.wrapped, s.y = regrid(s.cells, s.wrapped, s.y, cols, rows)
	if s.main != nil {
		s.main, s.mainWrap, s.mainY = regrid(s.main, s.mainWrap, s.mainY, cols, rows)
	}
	s.cols, s.rows = cols, rows
	s.x = min(s.x, cols-1)
	s.top, s.bot = 0, rows-1
	s.wrapNext = false
}

func regrid(old [][]rune, oldWrap []bool, y, cols, rows int) ([][]rune, []bool, int) {
	g, w := blankGrid(cols, rows)
	// Fewer rows: drop from the top, as a terminal does, so the cursor's line
	// survives.
	shift := 0
	if y >= rows {
		shift = y - rows + 1
	}
	for r := 0; r < rows && r+shift < len(old); r++ {
		src := old[r+shift]
		copy(g[r], src)
		if cols < len(src) && src[cols] == wideTail {
			g[r][cols-1] = 0 // half a wide rune cannot be kept
		}
		w[r] = oldWrap[r+shift]
	}
	return g, w, min(y-shift, rows-1)
}

// Write applies terminal output.
func (s *screen) Write(b []byte) {
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch s.state {
		case stGround:
			if len(s.pending) > 0 || c >= 0x80 {
				s.pending = append(s.pending, c)
				if !utf8.FullRune(s.pending) {
					if len(s.pending) < utf8.UTFMax {
						continue
					}
				}
				r, n := utf8.DecodeRune(s.pending)
				rest := s.pending[n:]
				s.pending = nil
				s.put(r)
				// A malformed sequence decodes one byte at a time; replay the rest.
				if len(rest) > 0 {
					s.Write(rest)
				}
				continue
			}
			s.ground(c)
		case stEsc:
			s.esc(c)
		case stEscInter:
			// The byte after a charset designation (ESC ( B and friends).
			s.state = stGround
		case stCSI:
			switch {
			case c >= 0x30 && c <= 0x3f:
				if (c == '?' || c == '>' || c == '<' || c == '=') && len(s.params) == 0 {
					s.private = c
				} else if len(s.params) < 64 {
					s.params = append(s.params, c)
				}
			case c >= 0x20 && c <= 0x2f:
				s.inter = c
			case c >= 0x40 && c <= 0x7e:
				s.state = stGround
				s.csi(c)
			case c == 0x1b:
				s.state = stEsc
			case c == 0x18 || c == 0x1a:
				s.state = stGround
			default:
				s.ground(c) // C0 controls take effect even inside a sequence
			}
		case stOSC, stString:
			s.strBytes++
			switch {
			case c == 0x07 && s.state == stOSC:
				s.state = stGround
			case s.strEsc && c == '\\':
				s.state = stGround
			case s.strBytes > maxStringBytes:
				s.state = stGround
			}
			s.strEsc = c == 0x1b
		}
	}
}

func (s *screen) ground(c byte) {
	switch c {
	case 0x1b:
		s.state = stEsc
	case '\r':
		s.x, s.wrapNext = 0, false
	case '\n', 0x0b, 0x0c:
		s.newline()
	case '\b':
		if s.wrapNext {
			s.wrapNext = false
		} else if s.x > 0 {
			s.x--
		}
	case '\t':
		s.x = min(s.cols-1, (s.x/8+1)*8)
		s.wrapNext = false
	default:
		if c >= 0x20 && c < 0x7f {
			s.put(rune(c))
		}
		// Other C0 controls (BEL, SO, SI…) and DEL draw nothing.
	}
}

func (s *screen) esc(c byte) {
	s.state = stGround
	switch c {
	case '[':
		s.state = stCSI
		s.params = s.params[:0]
		s.private, s.inter = 0, 0
	case ']':
		s.state, s.strEsc, s.strBytes = stOSC, false, 0
	case 'P', 'X', '^', '_':
		s.state, s.strEsc, s.strBytes = stString, false, 0
	case '(', ')', '*', '+', '-', '.', '/', '#', '%', ' ':
		s.state = stEscInter
	case '7':
		s.savedX, s.savedY = s.x, s.y
	case '8':
		s.x, s.y, s.wrapNext = min(s.savedX, s.cols-1), min(s.savedY, s.rows-1), false
	case 'D': // index
		s.index()
	case 'E': // next line
		s.x = 0
		s.newline()
	case 'M': // reverse index
		s.wrapNext = false
		if s.y == s.top {
			s.scrollDown(s.top, 1)
		} else if s.y > 0 {
			s.y--
		}
	case 'c': // full reset
		cols, rows := s.cols, s.rows
		lf := s.lineFeed
		*s = screen{autowrap: true, lineFeed: lf}
		s.resize(cols, rows)
	}
}

// newline is a line feed: the hook runs first, while the line still reads as the
// operator saw it.
func (s *screen) newline() {
	if s.lineFeed != nil {
		s.lineFeed()
	}
	s.index()
}

func (s *screen) index() {
	s.wrapNext = false
	if s.y == s.bot {
		s.scrollUp(s.top, 1)
	} else if s.y < s.rows-1 {
		s.y++
	}
}

func (s *screen) put(r rune) {
	w := runeWidth(r)
	if w == 0 {
		return // combining marks and zero-width characters: no cell of their own
	}
	if s.wrapNext && s.autowrap {
		s.wrapped[s.y] = true
		s.x = 0
		s.index()
	}
	s.wrapNext = false
	if w == 2 && s.x == s.cols-1 {
		// A wide character does not fit in the last column; the terminal leaves
		// it blank and wraps.
		if !s.autowrap {
			return
		}
		s.cells[s.y][s.x] = 0
		s.wrapped[s.y] = true
		s.x = 0
		s.index()
	}
	row := s.cells[s.y]
	if s.insert {
		copy(row[s.x+w:], row[s.x:])
	}
	s.clearHalf(s.x)
	row[s.x] = r
	if w == 2 {
		s.clearHalf(s.x + 1)
		row[s.x+1] = wideTail
	}
	s.x += w
	if s.x >= s.cols {
		s.x = s.cols - 1
		s.wrapNext = true
	}
}

// clearHalf blanks the other half of a wide rune about to be overwritten.
func (s *screen) clearHalf(x int) {
	row := s.cells[s.y]
	if x < 0 || x >= len(row) {
		return
	}
	if row[x] == wideTail && x > 0 {
		row[x-1] = 0
	}
	if x+1 < len(row) && row[x+1] == wideTail {
		row[x+1] = 0
	}
}

// param returns the i'th numeric parameter, or def when absent or zero.
func (s *screen) param(i, def int) int {
	n, idx, have := 0, 0, false
	for _, c := range s.params {
		if c == ';' || c == ':' {
			if idx == i {
				break
			}
			idx++
			n, have = 0, false
			continue
		}
		if idx == i && c >= '0' && c <= '9' {
			if n < 1<<16 {
				n = n*10 + int(c-'0')
			}
			have = true
		}
	}
	if idx < i || !have || n == 0 {
		return def
	}
	return n
}

func (s *screen) csi(final byte) {
	if s.inter != 0 {
		return // DECSCUSR and friends: cursor style, nothing that moves text
	}
	if s.private != 0 {
		if s.private == '?' && (final == 'h' || final == 'l') {
			s.privateModes(final == 'h')
		}
		return
	}
	n := s.param(0, 1)
	clampY := func(y int) int { return max(0, min(y, s.rows-1)) }
	switch final {
	case 'A': // up
		lim := 0
		if s.y >= s.top {
			lim = s.top
		}
		s.y = max(lim, s.y-n)
	case 'B', 'e': // down
		lim := s.rows - 1
		if s.y <= s.bot {
			lim = s.bot
		}
		s.y = min(lim, s.y+n)
	case 'C', 'a': // right
		s.x = min(s.cols-1, s.x+n)
	case 'D': // left
		s.x = max(0, s.x-n)
	case 'E':
		s.y, s.x = clampY(s.y+n), 0
	case 'F':
		s.y, s.x = clampY(s.y-n), 0
	case 'G', '`':
		s.x = max(0, min(n-1, s.cols-1))
	case 'd':
		s.y = clampY(n - 1)
	case 'H', 'f':
		s.y = clampY(s.param(0, 1) - 1)
		s.x = max(0, min(s.param(1, 1)-1, s.cols-1))
	case 'J':
		s.eraseDisplay(s.param(0, 0))
	case 'K':
		s.eraseLine(s.param(0, 0))
	case 'P': // delete characters
		row := s.cells[s.y]
		n = min(n, s.cols-s.x)
		copy(row[s.x:], row[s.x+n:])
		clear(row[s.cols-n:])
	case '@': // insert blanks
		row := s.cells[s.y]
		n = min(n, s.cols-s.x)
		copy(row[s.x+n:], row[s.x:])
		clear(row[s.x : s.x+n])
	case 'X': // erase characters
		clear(s.cells[s.y][s.x:min(s.cols, s.x+n)])
	case 'L': // insert lines
		if s.y >= s.top && s.y <= s.bot {
			s.scrollDown(s.y, n)
			s.x = 0
		}
	case 'M': // delete lines
		if s.y >= s.top && s.y <= s.bot {
			s.scrollUp(s.y, n)
			s.x = 0
		}
	case 'S':
		s.scrollUp(s.top, n)
	case 'T':
		if len(s.params) == 0 || s.param(1, 0) == 0 {
			s.scrollDown(s.top, n)
		}
	case 'r':
		top, bot := s.param(0, 1)-1, s.param(1, s.rows)-1
		if top < bot && bot < s.rows {
			s.top, s.bot = top, bot
			s.x, s.y = 0, 0
		}
	case 's':
		s.savedX, s.savedY = s.x, s.y
	case 'u':
		s.x, s.y = min(s.savedX, s.cols-1), min(s.savedY, s.rows-1)
	case 'h', 'l':
		if s.param(0, 0) == 4 {
			s.insert = final == 'h'
		}
	default:
		return // SGR (colour), device reports, and the rest: nothing to draw
	}
	s.wrapNext = false
}

func (s *screen) privateModes(on bool) {
	for i, n := 0, countParams(s.params); i < n; i++ {
		switch p := s.param(i, 0); p {
		case 7:
			s.autowrap = on
		case 1049:
			if on {
				s.savedX, s.savedY = s.x, s.y
			}
			s.setAlt(on, true)
			if !on {
				s.x, s.y = min(s.savedX, s.cols-1), min(s.savedY, s.rows-1)
			}
		case 1047, 47:
			s.setAlt(on, p == 1047)
		}
	}
}

// countParams is how many parameters a sequence carries, empty ones included.
func countParams(p []byte) int {
	if len(p) == 0 {
		return 0
	}
	n := 1
	for _, c := range p {
		if c == ';' {
			n++
		}
	}
	return n
}

func (s *screen) setAlt(on, clearIt bool) {
	if on == s.alt {
		if on && clearIt {
			s.cells, s.wrapped = blankGrid(s.cols, s.rows)
		}
		return
	}
	if on {
		s.main, s.mainWrap = s.cells, s.wrapped
		s.mainX, s.mainY, s.mainSavedX, s.mainSavedY = s.x, s.y, s.savedX, s.savedY
		s.cells, s.wrapped = blankGrid(s.cols, s.rows)
	} else {
		s.cells, s.wrapped = s.main, s.mainWrap
		s.x, s.y, s.savedX, s.savedY = s.mainX, s.mainY, s.mainSavedX, s.mainSavedY
		s.main, s.mainWrap = nil, nil
	}
	s.alt = on
	s.wrapNext = false
	s.top, s.bot = 0, s.rows-1
}

func (s *screen) eraseLine(mode int) {
	row := s.cells[s.y]
	switch mode {
	case 0:
		clear(row[s.x:])
		s.wrapped[s.y] = false
	case 1:
		clear(row[:s.x+1])
	case 2:
		clear(row)
		s.wrapped[s.y] = false
	}
}

func (s *screen) eraseDisplay(mode int) {
	switch mode {
	case 0:
		s.eraseLine(0)
		for y := s.y + 1; y < s.rows; y++ {
			clear(s.cells[y])
			s.wrapped[y] = false
		}
	case 1:
		for y := 0; y < s.y; y++ {
			clear(s.cells[y])
			s.wrapped[y] = false
		}
		s.eraseLine(1)
	case 2, 3:
		for y := range s.cells {
			clear(s.cells[y])
			s.wrapped[y] = false
		}
	}
}

// scrollUp moves rows from..bot up by n, blanking the bottom.
func (s *screen) scrollUp(from, n int) {
	n = min(n, s.bot-from+1)
	if n <= 0 {
		return
	}
	for y := from; y <= s.bot; y++ {
		if y+n <= s.bot {
			s.cells[y], s.cells[y+n] = s.cells[y+n], s.cells[y]
			s.wrapped[y] = s.wrapped[y+n]
		}
	}
	for y := s.bot - n + 1; y <= s.bot; y++ {
		clear(s.cells[y])
		s.wrapped[y] = false
	}
}

// scrollDown moves rows from..bot down by n, blanking the top.
func (s *screen) scrollDown(from, n int) {
	n = min(n, s.bot-from+1)
	if n <= 0 {
		return
	}
	for y := s.bot; y >= from; y-- {
		if y-n >= from {
			s.cells[y], s.cells[y-n] = s.cells[y-n], s.cells[y]
			s.wrapped[y] = s.wrapped[y-n]
		}
	}
	for y := from; y < from+n; y++ {
		clear(s.cells[y])
		s.wrapped[y] = false
	}
}

// line returns the cursor's line as the operator reads it: every row of it, when
// a long line has wrapped across several, with trailing blanks dropped. before is
// the part left of the cursor.
func (s *screen) line() (text string, before string) {
	first, last := s.span(s.y)
	var all, left []rune
	for y := first; y <= last; y++ {
		for x, r := range s.cells[y] {
			if r == wideTail {
				continue
			}
			if r == 0 {
				r = ' '
			}
			all = append(all, r)
			if y < s.y || (y == s.y && (x < s.x || (x == s.x && s.wrapNext))) {
				left = append(left, r)
			}
		}
	}
	return trimRight(all), string(left)
}

// linesAfter returns up to n lines following the cursor's, each joined across
// the rows it wrapped onto.
func (s *screen) linesAfter(n int) []string {
	_, last := s.span(s.y)
	var out []string
	for y := last + 1; y < s.rows && len(out) < n; {
		first, end := s.span(y)
		out = append(out, s.text(first, end))
		y = end + 1
	}
	return out
}

// span is the first and last row of the wrapped line row y belongs to.
func (s *screen) span(y int) (first, last int) {
	first, last = y, y
	for first > 0 && s.wrapped[first-1] {
		first--
	}
	for last < s.rows-1 && s.wrapped[last] {
		last++
	}
	return first, last
}

func (s *screen) text(first, last int) string {
	var rs []rune
	for y := first; y <= last; y++ {
		for _, r := range s.cells[y] {
			if r == wideTail {
				continue
			}
			if r == 0 {
				r = ' '
			}
			rs = append(rs, r)
		}
	}
	return trimRight(rs)
}

func trimRight(r []rune) string {
	n := len(r)
	for n > 0 && r[n-1] == ' ' {
		n--
	}
	return string(r[:n])
}

// runeWidth is how many cells r takes, as xterm draws it: none for combining
// marks and zero-width characters, two for East Asian wide characters and most
// emoji, one for everything else.
func runeWidth(r rune) int {
	switch {
	case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff:
		return 0
	case unicode.In(r, unicode.Mn, unicode.Me):
		return 0
	case r >= 0x1100 && r <= 0x115f,
		r >= 0x2e80 && r <= 0x303e,
		r >= 0x3041 && r <= 0x33ff,
		r >= 0x3400 && r <= 0x4dbf,
		r >= 0x4e00 && r <= 0x9fff,
		r >= 0xa000 && r <= 0xa4cf,
		r >= 0xac00 && r <= 0xd7a3,
		r >= 0xf900 && r <= 0xfaff,
		r >= 0xfe30 && r <= 0xfe4f,
		r >= 0xff00 && r <= 0xff60,
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f,
		r >= 0x1f900 && r <= 0x1f9ff,
		r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}

// String renders the screen, for tests and debugging.
func (s *screen) String() string {
	var out []byte
	for y, row := range s.cells {
		var rs []rune
		for _, r := range row {
			if r == wideTail {
				continue
			}
			if r == 0 {
				r = ' '
			}
			rs = append(rs, r)
		}
		out = append(out, trimRight(rs)...)
		if s.wrapped[y] {
			out = append(out, '\\')
		}
		out = append(out, '\n')
	}
	return string(out) + "cursor " + strconv.Itoa(s.y) + "," + strconv.Itoa(s.x)
}
