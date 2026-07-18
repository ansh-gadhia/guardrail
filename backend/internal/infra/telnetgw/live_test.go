package telnetgw

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// These run against a REAL telnet device, because the fake IOS in login_test.go
// can only prove the gateway is self-consistent. It cannot prove that an actual
// Cisco box prompts the way the regexes in login.go expect — and that is exactly
// where this gateway fails silently: a prompt we do not match means the
// credential is never typed, and the operator gets a login prompt they cannot
// answer, because a PAM never shows them the password. No unit test catches that,
// because the unit test's device prompts however I imagined it would.
//
// Skipped unless TELNET_ADDR names one, so `go test ./...` stays hermetic:
//
//	TELNET_ADDR=10.200.10.86:23 go test ./internal/infra/telnetgw/ -run Live -v
func liveTelnet(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("TELNET_ADDR")
	if addr == "" {
		t.Skip("set TELNET_ADDR=host:23 to run live telnet tests")
	}
	return addr
}

// TestLiveDeviceOffersAPromptWeRecognise dials the device and reads until it
// stops talking, then asserts that login.go's regexes match what actually came
// back.
//
// It never sends a credential: the point is to learn what the device asks, not
// to authenticate. That also makes it safe to run against production kit — it
// leaves nothing behind but a closed connection and, at worst, one line in the
// device's log.
func TestLiveDeviceOffersAPromptWeRecognise(t *testing.T) {
	addr := liveTelnet(t)

	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = raw.Close() }()

	c := newConn(raw)
	if err := c.hello(); err != nil {
		t.Fatalf("negotiate: %v", err)
	}

	// Read until the device goes quiet. A prompt is the device waiting, so
	// "stopped sending" IS the signal — there is no end-of-message marker.
	var out []byte
	buf := make([]byte, 4<<10)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_ = raw.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, rerr := c.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if rerr != nil {
			break
		}
	}

	if len(out) == 0 {
		t.Fatal("device sent nothing; the login regexes cannot match what does not arrive")
	}
	t.Logf("device said (%d bytes):\n%s", len(out), strings.TrimSpace(string(out)))

	// The window login.go actually matches against.
	window := out
	if len(window) > loginWindow {
		window = window[len(window)-loginWindow:]
	}
	text := string(window)

	switch {
	case passPrompt.MatchString(text):
		t.Log("MATCH: password prompt — a password-only vty line; the secret goes in first")
	case userPrompt.MatchString(text):
		t.Log("MATCH: username prompt — the credential needs a username saved with it")
	default:
		// Not a hard failure: this is diagnostic. It says precisely which regex
		// needs to grow, and shows the bytes to grow it against.
		t.Errorf("NO MATCH: neither prompt regex fires on the device's output.\n"+
			"tail = %q\nuserPrompt = %s\npassPrompt = %s\n"+
			"telnet would open to a prompt the operator cannot answer; widen the regex in login.go",
			tailOf(text, 120), userPrompt, passPrompt)
	}

	// Negotiation sanity: anything left in the data stream that looks like a raw
	// IAC means the parser leaked a command into what we treat as device output,
	// and that byte would land in the transcript as something the device "printed".
	if i := indexIAC(out); i >= 0 {
		t.Errorf("raw IAC (0xFF) at offset %d survived into device output; negotiation leaked", i)
	}
}

// TestLiveDeviceEntersCharacterMode checks the device agreed to the options that
// make a telnet console feel like a terminal rather than a form.
//
// Without remote echo and suppress-go-ahead, IOS stays line-at-a-time: no arrow
// keys, no tab completion, nothing arrives until Enter. That is the "laggy,
// not like SSH" complaint this gateway exists to fix, so it is worth asserting
// against the real device rather than a fake that agrees to whatever we ask.
func TestLiveDeviceEntersCharacterMode(t *testing.T) {
	addr := liveTelnet(t)

	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = raw.Close() }()

	c := newConn(raw)
	if err := c.hello(); err != nil {
		t.Fatalf("negotiate: %v", err)
	}

	// Drive the parser so the option replies are processed.
	buf := make([]byte, 4<<10)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = raw.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		if _, rerr := c.Read(buf); rerr != nil {
			break
		}
	}

	c.omu.Lock()
	echo, sga := c.theyWill[optEcho], c.theyWill[optSGA]
	c.omu.Unlock()

	t.Logf("device performs: ECHO=%v SUPPRESS-GO-AHEAD=%v", echo, sga)
	if !echo && !sga {
		t.Error("device agreed to neither remote echo nor suppress-go-ahead; " +
			"the console will be line-at-a-time, which is the bug this gateway was built to fix")
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func indexIAC(b []byte) int {
	for i, x := range b {
		if x == cmdIAC {
			return i
		}
	}
	return -1
}
