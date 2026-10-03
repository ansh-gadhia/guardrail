package term

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kinds of timeline event the command log writes.
const (
	// EventCommand is a line the operator entered: a shell command, a line of
	// device configuration, or an answer typed at a program's prompt. Data:
	// "command", and "prompt" — what the device showed in front of it, which
	// says who and where the operator was (user, host, directory, config mode).
	EventCommand = "command"
	// EventHiddenInput is an answer typed at a prompt that did not echo it: a
	// password for sudo, an enable secret, a key passphrase. Data: "prompt"
	// only. What was typed is never recorded, and neither is how long it was.
	EventHiddenInput = "hidden_input"
)

// CommandLog reads the commands an operator runs off the operator's screen.
//
// A terminal session's recording is everything the device printed, which is
// complete and also unreadable at a glance: finding the one command that
// mattered in an hour of output means reading the hour. The command log puts
// each command on the session's timeline, where a reviewer reads the session
// as a list and jumps to the moment that matters.
//
// It does not log keystrokes, for the reason the recorder gives: what an
// operator types includes every password they type, and a password prompt does
// not echo. The keyboard is used only for WHEN — the operator pressed Enter,
// so the line on the screen is about to be submitted — and the command is read
// from the screen, which is to say from the device's echo of it. That is also
// what makes it right: the screen shows the command after tab completion,
// history recall, and every correction, which no reading of the keystrokes can
// reconstruct. And an answer typed at a prompt that does not echo leaves an
// empty line, so it is recorded as "something was typed at this prompt" and
// nothing more.
//
// A nil *CommandLog is valid and does nothing.
type CommandLog struct {
	mu     sync.Mutex
	scr    *screen
	record func(kind string, data map[string]any)
	now    func() time.Time

	// enters are the operator's Enter presses the device has not yet answered
	// by starting a new line. Usually there is at most one; several when lines
	// are pasted or typed ahead of a slow command.
	enters []enter
	// prompt is what stood left of the cursor when the operator started typing
	// the current line: the prompt, whatever it looks like.
	prompt string
	fresh  bool // nothing typed on this line yet; the next key learns the prompt
	// typed counts printable keys on the current line, net of backspaces. Only
	// the count is kept, and only to tell a prompt that hid what was typed from
	// one where nothing was typed at all.
	typed   int
	pasteNL int // line breaks inside a bracketed paste on the current line
	// Input escape-sequence state: arrow keys and the paste markers are not
	// typing.
	inEsc   int
	escArg  []byte
	inPaste bool
	lastCR  bool
	written int
}

type enter struct {
	at    time.Time
	typed int
	lines int // lines the submitted text spans; more than one after a paste
	// blind marks an Enter pressed away from any prompt: into a program's
	// output, or typed ahead of it. Only the prompt actually seen may answer
	// it, never a line that merely looks like one — ping's "0% packet loss"
	// has the shape of a zsh prompt.
	blind bool
}

const (
	// maxPendingEnters bounds the queue. Enter held down, or a large paste into
	// a device that echoes slowly, should not grow it without limit.
	maxPendingEnters = 256
	// enterTTL is how long an Enter waits to be matched to a submitted line. One
	// pressed while a program was printing, which no prompt follows, must not be
	// paired with whatever prompt-shaped line appears minutes later.
	enterTTL = 30 * time.Second
	// maxPromptRunes: anything longer left of the cursor is not a prompt, it is
	// output the cursor happened to be at the end of.
	maxPromptRunes = 256
	// maxCommandBytes bounds one entry. A pasted script is still one entry.
	maxCommandBytes = 4096
	// maxPasteLines bounds how much of a pasted block is read back.
	maxPasteLines = 200
	// MaxCommands caps one session's command entries, so a session cannot write
	// unbounded rows. The transcript has everything past it.
	MaxCommands = 5000
)

// NewCommandLog starts a command log for a terminal of the given size. record
// receives each entry; it is called with the log's lock held, so it must not
// block (see Activity, which queues).
func NewCommandLog(cols, rows int, record func(kind string, data map[string]any)) *CommandLog {
	if cols <= 0 || rows <= 0 {
		cols, rows = 80, 24
	}
	l := &CommandLog{scr: newScreen(cols, rows), record: record, now: time.Now, fresh: true}
	l.scr.lineFeed = l.lineFeed
	return l
}

// Output applies device output to the screen. Called on the session's output
// path, so it does no I/O.
func (l *CommandLog) Output(b []byte) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.scr.Write(b)
}

// Resize follows the operator's terminal size.
func (l *CommandLog) Resize(cols, rows int) {
	if l == nil || cols <= 0 || rows <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.scr.resize(cols, rows)
}

// Input notes what the operator's keys mean for the line being typed. The bytes
// themselves are not kept.
func (l *CommandLog) Input(b []byte) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.scr.alt {
		// A full-screen program has the keyboard. Its Enter is not a command, and
		// whatever was pending is moot once the shell's screen is set aside.
		l.enters = l.enters[:0]
		l.typed, l.pasteNL, l.fresh, l.inEsc, l.inPaste = 0, 0, true, 0, false
		return
	}
	for _, c := range b {
		if l.inEsc > 0 {
			l.escape(c)
			continue
		}
		if c == '\n' && l.lastCR {
			// The second half of a CRLF; the Enter was counted on the CR.
			l.lastCR = false
			continue
		}
		l.lastCR = c == '\r'
		l.learn()
		switch {
		case c == '\r' || c == '\n':
			if l.inPaste {
				// Pasted line breaks are part of the line until the operator
				// presses Enter: a shell in bracketed-paste mode waits for it.
				l.pasteNL++
				break
			}
			l.submit()
		case c == 0x1b:
			l.inEsc = 1
		case c == 0x03 || c == 0x04 || c == 0x15:
			// Ctrl-C and Ctrl-D abandon the line; Ctrl-U clears it.
			l.typed, l.pasteNL = 0, 0
			if c != 0x15 {
				l.fresh = true
			}
		case c == 0x7f || c == 0x08:
			l.typed = max(0, l.typed-1)
		case c >= 0x20:
			l.typed++
		}
	}
}

// escape follows one byte of an input escape sequence: ESC [ ... final, ESC O x,
// or ESC x. Only the bracketed-paste markers mean anything here.
func (l *CommandLog) escape(c byte) {
	switch l.inEsc {
	case 1:
		switch c {
		case '[':
			l.inEsc, l.escArg = 2, l.escArg[:0]
		case 'O':
			l.inEsc = 3
		default:
			l.inEsc = 0
		}
	case 2:
		switch {
		case c >= 0x30 && c <= 0x3f:
			if len(l.escArg) < 8 {
				l.escArg = append(l.escArg, c)
			}
		case c >= 0x40 && c <= 0x7e:
			if c == '~' {
				switch string(l.escArg) {
				case "200":
					l.inPaste = true
				case "201":
					l.inPaste = false
				}
			}
			l.inEsc = 0
		default:
			l.inEsc = 0
		}
	default:
		l.inEsc = 0
	}
}

// submit records an Enter. The line is read when the device answers it.
func (l *CommandLog) submit() {
	if len(l.enters) >= maxPendingEnters {
		l.enters = l.enters[1:]
	}
	_, before := l.scr.line()
	_, _, atPrompt := splitPrompt(before, l.prompt, true)
	l.enters = append(l.enters, enter{
		at: l.now(), typed: l.typed, lines: 1 + min(l.pasteNL, maxPasteLines), blind: !atPrompt,
	})
	l.typed, l.pasteNL, l.fresh = 0, 0, true
}

// learn takes the prompt from the screen when the operator starts a new line:
// whatever stands left of the cursor before anything is typed is the prompt.
// Not when earlier lines are still unanswered — then the operator is typing
// ahead, the screen does not show this line's prompt yet, and the last one
// learned is the best guess.
func (l *CommandLog) learn() {
	if !l.fresh {
		return
	}
	l.fresh = false
	l.expire()
	if len(l.enters) > 0 {
		return
	}
	_, before := l.scr.line()
	switch n := utf8.RuneCountInString(before); {
	case n == 0:
		// Nothing left of the cursor: a program reading input with no prompt
		// of its own. Keep the shell's; it is the one that will come back.
	case n > maxPromptRunes:
		l.prompt = ""
	default:
		l.prompt = before
	}
}

func (l *CommandLog) expire() {
	now := l.now()
	i := 0
	for i < len(l.enters) && now.Sub(l.enters[i].at) > enterTTL {
		i++
	}
	l.enters = l.enters[i:]
}

// lineFeed runs as the device moves the cursor off a line. If an Enter is
// waiting and the line is a submitted one — it starts with a prompt — this is
// where it is read.
func (l *CommandLog) lineFeed() {
	if len(l.enters) == 0 || l.scr.alt {
		return
	}
	l.expire()
	if len(l.enters) == 0 {
		return
	}
	e := l.enters[0]
	text, _ := l.scr.line()
	prompt, cmd, ok := splitPrompt(text, l.prompt, !e.blind)
	if !ok || strings.HasSuffix(cmd, "^C") {
		// Output, or a line abandoned with Ctrl-C: not an answer to the Enter.
		return
	}
	l.enters = l.enters[1:]
	if e.lines > 1 {
		// A pasted block: the shell has redrawn it below the prompt, one row per
		// pasted line, and is about to run it as one.
		rest := l.scr.linesAfter(e.lines - 1)
		cmd = strings.TrimRight(strings.Join(append([]string{cmd}, rest...), "\n"), "\n ")
	}
	l.emit(prompt, cmd, e.typed)
}

func (l *CommandLog) emit(prompt, cmd string, typed int) {
	if l.record == nil || l.written >= MaxCommands {
		return
	}
	prompt = clean(prompt, maxPromptRunes*4)
	hidden := cmd == "" && typed > 0 && !isShellPrompt(prompt)
	if hidden || secretPrompt.MatchString(prompt) {
		// Typed at a prompt that hid it, or one that asked for a secret. A device
		// that echoes a password back (some print asterisks, a few print it)
		// does not get it written down here. A shell's own prompt is excluded
		// from the first test: an empty line there means the operator typed and
		// then erased, not that the shell hid anything.
		l.written++
		l.record(EventHiddenInput, map[string]any{"prompt": prompt})
		return
	}
	if cmd == "" {
		return // Enter on an empty line
	}
	data := map[string]any{"command": clean(cmd, maxCommandBytes), "prompt": prompt}
	if len(cmd) > maxCommandBytes {
		data["truncated"] = true
	}
	l.written++
	l.record(EventCommand, data)
}

// clean drops control characters and bounds the length, on a rune boundary.
func clean(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

var (
	// Prompts the learned one does not cover: lines typed ahead or pasted, whose
	// prompt was not on screen when typing started. Shells (user@host:~$, root#,
	// PS C:\>, >>>, and the arrow prompts of zsh themes), and network operating
	// systems, which put no space before the command (Router#, R1(config-if)#,
	// <Huawei>, [~HUAWEI-GE0/0/1]).
	shellPrompt   = regexp.MustCompile(`^(\S.{0,160}?[$#%>❯➜λ»])(?:\s+(.*))?$`)
	networkPrompt = regexp.MustCompile(`^([A-Za-z0-9][\w.\-/:@]*(?:\([\w.\-/:]+\))?[#>]|<[\w.\-]+>|\[[~*]?[\w.\-/:]+\])(.*)$`)
	// secretPrompt is a prompt asking for something that must not be written
	// down, whatever the device does with the echo.
	secretPrompt = regexp.MustCompile(`(?i)(password|passphrase|passcode|passwd|\bpin\b|secret|otp|one-time|verification code|token code)[^$#>]{0,60}[:?]\s*$`)
)

// isShellPrompt reports whether a prompt is a command prompt rather than a
// question a program asked.
func isShellPrompt(p string) bool {
	return shellPrompt.MatchString(p) || networkPrompt.MatchString(p)
}

// splitPrompt separates a submitted line into prompt and command. learned is
// the prompt seen when the line was started, which covers prompts of any shape;
// failing that, and when generic allows it, the line must look like a prompt.
func splitPrompt(line, learned string, generic bool) (prompt, cmd string, ok bool) {
	if p := strings.TrimRight(learned, " "); p != "" && strings.HasPrefix(line, p) {
		return p, strings.TrimSpace(line[len(p):]), true
	}
	if !generic {
		return "", "", false
	}
	if m := shellPrompt.FindStringSubmatch(line); m != nil {
		return m[1], strings.TrimSpace(m[2]), true
	}
	if m := networkPrompt.FindStringSubmatch(line); m != nil {
		return m[1], strings.TrimSpace(m[2]), true
	}
	return "", "", false
}
