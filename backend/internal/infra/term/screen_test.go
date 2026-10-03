package term

import (
	"strings"
	"testing"
)

func lineAfter(cols, rows int, out ...string) (string, string) {
	s := newScreen(cols, rows)
	for _, o := range out {
		s.Write([]byte(o))
	}
	return s.line()
}

func TestScreen_LineEditing(t *testing.T) {
	cases := []struct {
		name string
		out  []string
		want string
	}{
		{"plain", []string{"$ ls -la"}, "$ ls -la"},
		{"backspace erase", []string{"$ lsx\b \b"}, "$ ls"},
		{"overwrite after CR", []string{"progress 10%\rprogress 100%"}, "progress 100%"},
		{"insert character", []string{"$ echo world\b\b\b\b\b\x1b[6@hello "}, "$ echo hello world"},
		{"insert mode", []string{"$ echo world\b\b\b\b\b\x1b[4hhello \x1b[4l"}, "$ echo hello world"},
		{"delete character", []string{"$ echo hxello\b\b\b\b\b\x1b[P"}, "$ echo hello"},
		{"erase to end", []string{"$ echo long tail\b\b\b\b\b\x1b[K"}, "$ echo long"},
		{"erase whole line", []string{"junk\x1b[2K\r$ ok"}, "$ ok"},
		{"cursor right", []string{"$ ab\rx\x1b[2Cc"}, "x ac"},
		{"column absolute", []string{"$ abcdef\x1b[3GX"}, "$ Xbcdef"},
		{"colour does not draw", []string{"\x1b[01;32muser@host\x1b[00m:\x1b[01;34m~\x1b[00m$ ls"}, "user@host:~$ ls"},
		{"title does not draw", []string{"\x1b]0;user@host: ~\x07$ ls"}, "$ ls"},
		{"title ended by ST", []string{"\x1b]0;title\x1b\\$ ls"}, "$ ls"},
		{"charset select", []string{"\x1b(B$ ls"}, "$ ls"},
		{"utf-8 split across writes", []string{"$ echo caf\xc3", "\xa9"}, "$ echo café"},
		{"wide characters", []string{"$ echo 日本"}, "$ echo 日本"},
		{"invalid utf-8", []string{"$ a\xffb"}, "$ a\uFFFDb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := lineAfter(40, 5, c.out...); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// A line longer than the terminal is wrapped by the terminal, and read back as
// the one line it is.
func TestScreen_WrappedLine(t *testing.T) {
	cmd := "$ echo " + strings.Repeat("a", 30)
	s := newScreen(10, 6)
	s.Write([]byte(cmd))
	got, before := s.line()
	if got != cmd || before != cmd {
		t.Errorf("got %q / %q", got, before)
	}
	// readline's own margin handling: the character that wraps, then CR, then
	// the rest drawn again from the start of the new row.
	s = newScreen(10, 6)
	s.Write([]byte("$ 12345678x\rxyz"))
	if got, _ := s.line(); got != "$ 12345678xyz" {
		t.Errorf("readline wrap: %q", got)
	}
	// A wide character that does not fit in the last column wraps whole.
	s = newScreen(4, 3)
	s.Write([]byte("abc日"))
	if got, _ := s.line(); got != "abc 日" {
		t.Errorf("wide at margin: %q", got)
	}
	// An explicit newline is a new line, not a continuation.
	s = newScreen(10, 6)
	s.Write([]byte("$ first\r\n$ second"))
	if got, _ := s.line(); got != "$ second" {
		t.Errorf("after newline: %q", got)
	}
}

func TestScreen_AlternateScreen(t *testing.T) {
	s := newScreen(20, 5)
	s.Write([]byte("$ vi notes"))
	s.Write([]byte("\x1b[?1049h\x1b[H\x1b[2Jediting text\r\n~\r\n~"))
	if !s.alt {
		t.Fatal("not on the alternate screen")
	}
	s.Write([]byte("\x1b[?1049l"))
	if s.alt {
		t.Fatal("still on the alternate screen")
	}
	if got, _ := s.line(); got != "$ vi notes" {
		t.Errorf("the shell's screen did not come back: %q", got)
	}
	// Two-parameter form, as some programs send it.
	s.Write([]byte("\x1b[?1;1049h"))
	if !s.alt {
		t.Error("?1;1049h did not switch")
	}
}

func TestScreen_ScrollingAndRegions(t *testing.T) {
	s := newScreen(10, 3)
	s.Write([]byte("one\r\ntwo\r\nthree\r\nfour"))
	if !strings.HasPrefix(s.String(), "two\nthree\nfour\n") {
		t.Errorf("scrolled:\n%s", s)
	}
	// A scroll region keeps the rows outside it.
	s = newScreen(10, 4)
	s.Write([]byte("top\x1b[2;3r\x1b[2;1Ha\r\nb\r\nc"))
	if !strings.HasPrefix(s.String(), "top\nb\nc\n") {
		t.Errorf("region:\n%s", s)
	}
	// Reverse index at the top scrolls down.
	s = newScreen(10, 3)
	s.Write([]byte("x\r\ny\x1b[H\x1bMz"))
	if !strings.HasPrefix(s.String(), "z\nx\ny\n") {
		t.Errorf("reverse index:\n%s", s)
	}
	// Clear screen, as `clear` sends it.
	s.Write([]byte("\x1b[H\x1b[2J\x1b[3J$ "))
	if got, _ := s.line(); got != "$" {
		t.Errorf("after clear: %q", got)
	}
}

func TestScreen_ResizeKeepsTheCursorLine(t *testing.T) {
	s := newScreen(20, 10)
	for i := 0; i < 9; i++ {
		s.Write([]byte("line\r\n"))
	}
	s.Write([]byte("$ cmd"))
	s.resize(8, 3)
	if got, _ := s.line(); got != "$ cmd" {
		t.Errorf("after shrinking: %q", got)
	}
	s.resize(100, 50)
	s.Write([]byte(" more"))
	if got, _ := s.line(); got != "$ cmd more" {
		t.Errorf("after growing: %q", got)
	}
}

// Nothing a device sends may crash the session it is part of.
func TestScreen_HostileInput(t *testing.T) {
	s := newScreen(10, 4)
	inputs := []string{
		"\x1b[99999999999999999999A\x1b[99999;99999H\x1b[99999P\x1b[99999@\x1b[99999X\x1b[99999L\x1b[99999M",
		"\x1b[0;0r\x1b[5;2r\x1b[99;1r\x1b[99999S\x1b[99999T",
		"\x1b]" + strings.Repeat("x", 10000), // an OSC that never ends
		"\x1bP" + strings.Repeat("y", 10000) + "\x1b\\",
		"\x1b[" + strings.Repeat("1;", 1000) + "m",
		"\x1b[?1049h\x1b[?1049h\x1b[?1049l\x1b[?1049l\x1b[?47l",
		"\x1bc\x1b7\x1b8\x1b[s\x1b[u\t\t\t\t\t\b\b\b",
		"日本語日本語日本語\x1b[2D\x1b[P\x1b[@",
	}
	for _, in := range inputs {
		s.Write([]byte(in))
		s.resize(3, 2)
		s.Write([]byte(in))
		s.resize(10, 4)
		_, _ = s.line()
		_ = s.linesAfter(5)
	}
	// After an unterminated OSC is abandoned, ordinary text draws again.
	s = newScreen(20, 3)
	s.Write([]byte("\x1b]" + strings.Repeat("x", maxStringBytes+10) + "$ ok"))
	if got, _ := s.line(); !strings.HasSuffix(got, "ok") {
		t.Errorf("text after an abandoned OSC: %q", got)
	}
}
