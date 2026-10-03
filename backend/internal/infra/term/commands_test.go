package term

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type entry struct {
	kind    string
	command string
	prompt  string
}

// replay feeds a recorded exchange through a command log on a clock that runs
// at the recording's pace, and returns what it logged.
func replay(t *testing.T, events []struct {
	T  string `json:"t"`
	D  string `json:"d"`
	Ms int64  `json:"ms"`
}) []entry {
	t.Helper()
	var got []entry
	l := NewCommandLog(80, 24, func(kind string, data map[string]any) {
		e := entry{kind: kind}
		e.command, _ = data["command"].(string)
		e.prompt, _ = data["prompt"].(string)
		got = append(got, e)
	})
	start := time.Now()
	var at time.Time
	l.now = func() time.Time { return at }
	for _, ev := range events {
		at = start.Add(time.Duration(ev.Ms) * time.Millisecond)
		if ev.T == "in" {
			l.Input([]byte(ev.D))
		} else {
			l.Output([]byte(ev.D))
		}
	}
	return got
}

// The fixtures are real: bash 5.1 on Ubuntu 22.04 over SSH with a PTY, driven
// one keystroke at a time the way a person types, and recorded byte for byte.
// That matters more here than anywhere: what readline emits for an edit, a
// history recall or a long line is not what one would guess, and a synthetic
// stream would only test the guess.
func TestCommandLog_RealBash(t *testing.T) {
	raw, err := os.ReadFile("testdata/bash_sessions.json")
	if err != nil {
		t.Fatal(err)
	}
	var sessions map[string][]struct {
		T  string `json:"t"`
		D  string `json:"d"`
		Ms int64  `json:"ms"`
	}
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatal(err)
	}

	cmd := func(c string) entry { return entry{kind: EventCommand, command: c} }
	cases := map[string][]entry{
		"basic":   {cmd("ls /"), cmd("pwd")},
		"edit":    {cmd("echo hello world")},              // "helo", two backspaces, "llo world"
		"insert":  {cmd("echo hello world")},              // "echo world", cursor left, "hello " inserted
		"history": {cmd("echo first"), cmd("echo first")}, // the second recalled with the up arrow
		"tab":     {cmd("echo tab done")},                 // "ech" completed with Tab
		"ctrlr":   {cmd("echo needle here"), cmd("echo other"), cmd("echo needle here")},
		"long":    {cmd("echo " + strings.Repeat("a", 100) + " " + strings.Repeat("b", 40))},
		// Typed across the right margin, where readline wraps by hand.
		"longtyped": {cmd("echo " + strings.Repeat("x", 85) + " end")},
		// The password typed at sudo's prompt is not in it — only that one was.
		"sudo":   {cmd("sudo -k; sudo true"), {kind: EventHiddenInput, prompt: "[sudo] password for op:"}},
		"vim":    {cmd("vi /tmp/x"), cmd("cat /tmp/x")}, // nothing typed inside vi
		"cancel": {cmd("echo yes")},                     // "echo nope" was abandoned with Ctrl-C
		// Pasted with no Enter after it: bash waits, so nothing ran.
		"paste": nil,
		// Pasted, then Enter: one entry, both lines.
		"pastebr":    {cmd("echo one\necho two")},
		"pastebrnl":  {cmd("echo one\necho two")},
		"pasteplain": {cmd("echo three"), cmd("echo four")},
		"read":       {cmd("read -p 'Continue? [y/N] ' a"), {kind: EventCommand, command: "y", prompt: "Continue? [y/N]"}},
		"clear":      {cmd("clear"), cmd("cd /tmp"), cmd("pwd")},
		// "echo after" typed while sleep ran: the terminal echoed it early, and
		// it is logged once, when bash actually took it.
		"typeahead": {cmd("sleep 1"), cmd("echo after")},
		// Enter pressed while ping printed: not a command.
		"ping":      {cmd("ping -c 3 127.0.0.1")},
		"multiline": {cmd("for i in 1 2; do"), {kind: EventCommand, command: "echo $i", prompt: ">"}, {kind: EventCommand, command: "done", prompt: ">"}},
		"less":      {cmd("seq 100 | less")}, // Enter inside less scrolled; it did not run anything
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			evs, ok := sessions[name]
			if !ok {
				t.Fatalf("no fixture %q", name)
			}
			got := replay(t, evs)
			if len(got) != len(want) {
				t.Fatalf("got %d entries %+v, want %d %+v", len(got), got, len(want), want)
			}
			for i := range want {
				g, w := got[i], want[i]
				if g.kind != w.kind || g.command != w.command {
					t.Errorf("entry %d: got %s %q, want %s %q", i, g.kind, g.command, w.kind, w.command)
				}
				if w.prompt != "" && g.prompt != w.prompt {
					t.Errorf("entry %d: prompt %q, want %q", i, g.prompt, w.prompt)
				}
				if w.prompt == "" && w.kind == EventCommand && !strings.HasPrefix(g.prompt, "op@") {
					t.Errorf("entry %d: prompt %q, want the shell's", i, g.prompt)
				}
			}
		})
	}
	// The prompt says where the operator was.
	got := replay(t, sessions["clear"])
	if !strings.HasSuffix(got[2].prompt, ":/tmp$") {
		t.Errorf("after cd /tmp the prompt is %q", got[2].prompt)
	}
}

// script plays a hand-written exchange: "<" is the operator, ">" the device.
func script(t *testing.T, steps ...string) []entry {
	t.Helper()
	var got []entry
	l := NewCommandLog(80, 24, func(kind string, data map[string]any) {
		e := entry{kind: kind}
		e.command, _ = data["command"].(string)
		e.prompt, _ = data["prompt"].(string)
		got = append(got, e)
	})
	for _, s := range steps {
		switch s[0] {
		case '<':
			l.Input([]byte(s[1:]))
		case '>':
			l.Output([]byte(s[1:]))
		}
	}
	return got
}

// A Cisco-style device: no space after the prompt, the prompt changing with the
// configuration mode, a pasted block of configuration, and an enable password
// that is not echoed.
func TestCommandLog_NetworkDevice(t *testing.T) {
	got := script(t,
		">\r\nR1>",
		"<enable\r", ">enable\r\nPassword: ",
		"<hunter2\r", ">\r\nR1#",
		"<conf t\r", ">conf t\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\nR1(config)#",
		// Pasted in one go, echoed line by line as the device takes them.
		"<interface Gi0/1\rdescription uplink\rexit\r",
		">interface Gi0/1\r\nR1(config-if)#",
		">description uplink\r\nR1(config-if)#",
		">exit\r\nR1(config)#",
	)
	want := []entry{
		{EventCommand, "enable", "R1>"},
		{EventHiddenInput, "", "Password:"},
		{EventCommand, "conf t", "R1#"},
		{EventCommand, "interface Gi0/1", "R1(config)#"},
		{EventCommand, "description uplink", "R1(config-if)#"},
		{EventCommand, "exit", "R1(config-if)#"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A device that echoes what is typed at a password prompt — some print
// asterisks, a few print the password itself — still does not get it logged.
func TestCommandLog_EchoedSecretIsNotLogged(t *testing.T) {
	for _, echo := range []string{"********", "hunter2"} {
		got := script(t,
			">\r\nlogin: admin\r\nPassword: ",
			"<hunter2\r", ">"+echo+"\r\n$ ",
		)
		if len(got) != 1 || got[0].kind != EventHiddenInput || got[0].command != "" {
			t.Errorf("echo %q: got %+v", echo, got)
		}
		for _, e := range got {
			if strings.Contains(e.command+e.prompt, "hunter2") || strings.Contains(e.command, "*") {
				t.Errorf("echo %q: the secret reached the log: %+v", echo, e)
			}
		}
	}
}

// Typing and erasing at a shell prompt is an empty line, not a hidden answer.
func TestCommandLog_ErasedLineIsNothing(t *testing.T) {
	got := script(t,
		">user@host:~$ ",
		"<abc", ">abc",
		"<\x7f\x7f\x7f", ">\b \b\b \b\b \b",
		"<\r", ">\r\nuser@host:~$ ",
	)
	if len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// An Enter that no prompt-shaped line answers expires; it is not attached to a
// line that turns up much later.
func TestCommandLog_StaleEnterExpires(t *testing.T) {
	var got []entry
	l := NewCommandLog(80, 24, func(kind string, data map[string]any) {
		c, _ := data["command"].(string)
		got = append(got, entry{kind: kind, command: c})
	})
	now := time.Now()
	l.now = func() time.Time { return now }
	l.Output([]byte("$ cat\r\n"))
	l.Input([]byte("\r")) // Enter while a program reads its input
	l.Output([]byte("\r\n"))
	now = now.Add(time.Minute)
	l.Output([]byte("root# made-up output line\r\n"))
	if len(got) != 0 {
		t.Errorf("a stale Enter was matched: %+v", got)
	}
}

func TestCommandLog_Limits(t *testing.T) {
	n := 0
	l := NewCommandLog(80, 24, func(string, map[string]any) { n++ })
	l.Output([]byte("$ "))
	for i := 0; i < MaxCommands+10; i++ {
		l.Input([]byte("x\r"))
		l.Output([]byte("x\r\n$ "))
	}
	if n != MaxCommands {
		t.Errorf("logged %d entries, want the cap %d", n, MaxCommands)
	}

	var long string
	l = NewCommandLog(200, 60, func(_ string, d map[string]any) { long, _ = d["command"].(string) })
	l.Output([]byte("$ "))
	big := strings.Repeat("é", maxCommandBytes) // two bytes each: the cut must land on a rune
	l.Input([]byte(big + "\r"))
	l.Output([]byte(big + "\r\n"))
	if len(long) == 0 || len(long) > maxCommandBytes || !strings.HasPrefix(long, "éé") || strings.ContainsRune(long, '�') {
		t.Errorf("long command kept as %d bytes", len(long))
	}

	var nilLog *CommandLog
	nilLog.Input([]byte("x\r"))
	nilLog.Output([]byte("x"))
	nilLog.Resize(10, 10)
}
