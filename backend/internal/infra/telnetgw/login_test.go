package telnetgw

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// readLine reads one CR-LF terminated line from the device side.
//
// Unbuffered on purpose: a bufio.Reader built per call can read ahead and drop
// whatever it buffered when it goes out of scope, which would make these tests
// fail intermittently for a reason that has nothing to do with the gateway.
func readLine(c net.Conn) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := c.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return strings.TrimRight(string(line), "\r"), err
		}
	}
}

func testGateway() *Gateway { return &Gateway{cfg: DefaultConfig(), sessions: nil} }

func pwCred(user, secret string) access.Credential {
	return access.Credential{Injection: InjectPassword, Username: user, Secret: secret}
}

func TestLoginTypesTheCredentialAtCiscoPrompts(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	typed := make(chan [2]string, 1)
	go func() {
		// A real IOS login: banner, Username:, Password:, then user EXEC.
		_, _ = far.Write([]byte("\r\nUser Access Verification\r\n\r\nUsername: "))
		u, _ := readLine(far)
		_, _ = far.Write([]byte("\r\nPassword: "))
		p, _ := readLine(far)
		_, _ = far.Write([]byte("\r\nRouter>"))
		typed <- [2]string{u, p}
	}()

	banner, err := g.login(c, pwCred("cisco", "s3cret"), time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	got := <-typed
	if got[0] != "cisco" || got[1] != "s3cret" {
		t.Errorf("device received %q/%q, want cisco/s3cret", got[0], got[1])
	}
	// The banner is what the operator sees and what the transcript starts with.
	if !strings.Contains(string(banner), "User Access Verification") {
		t.Errorf("banner = %q, want the device's own login output", banner)
	}
}

func TestLoginHandlesAPasswordOnlyLine(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	// A vty line with just `password x` and no `login local` never asks who you
	// are. This is the commonest Cisco config there is, so a gateway that waits
	// for a username prompt would hang on most of the fleet.
	got := make(chan string, 1)
	go func() {
		_, _ = far.Write([]byte("\r\nPassword: "))
		p, _ := readLine(far)
		_, _ = far.Write([]byte("\r\nswitch>"))
		got <- p
	}()

	if _, err := g.login(c, pwCred("", "onlypass"), time.Now().Add(3*time.Second)); err != nil {
		t.Fatalf("login: %v", err)
	}
	if p := <-got; p != "onlypass" {
		t.Errorf("device received %q, want onlypass", p)
	}
}

func TestLoginRefusesAWebCredential(t *testing.T) {
	c, _ := pipeConn(t)
	g := testGateway()

	// Binding a web credential to a CLI device is the commonest first-time
	// mistake. It must be a 422 with a sentence the operator can act on, not a
	// 500 and not a silent attempt to type a form password at a router.
	_, err := g.login(c, access.Credential{Injection: "basic", Username: "u", Secret: "p"}, time.Now().Add(time.Second))
	if !errors.Is(err, access.ErrCredentialUnusable) {
		t.Fatalf("err = %v, want ErrCredentialUnusable", err)
	}
	if !strings.Contains(err.Error(), InjectPassword) {
		t.Errorf("err = %q, want it to name the injection method to use", err)
	}
}

func TestLoginRejectsWhenTheDeviceAsksAgain(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	go func() {
		_, _ = far.Write([]byte("\r\nPassword: "))
		_, _ = readLine(far)
		// A second prompt is IOS saying no.
		_, _ = far.Write([]byte("\r\nPassword: "))
	}()

	_, err := g.login(c, pwCred("", "wrong"), time.Now().Add(3*time.Second))
	if !errors.Is(err, access.ErrCredentialUnusable) {
		t.Fatalf("err = %v, want ErrCredentialUnusable — a re-prompt is a rejection", err)
	}
}

func TestLoginRejectsOnAnExplicitFailureMessage(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	go func() {
		_, _ = far.Write([]byte("\r\nUsername: "))
		_, _ = readLine(far)
		_, _ = far.Write([]byte("\r\nPassword: "))
		_, _ = readLine(far)
		_, _ = far.Write([]byte("\r\n% Login invalid\r\n\r\nUsername: "))
	}()

	_, err := g.login(c, pwCred("u", "wrong"), time.Now().Add(3*time.Second))
	if !errors.Is(err, access.ErrCredentialUnusable) {
		t.Fatalf("err = %v, want ErrCredentialUnusable", err)
	}
}

func TestLoginIsNotFooledByTheWordPasswordInABanner(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	// Management banners are full of the word. Firing on it would send the
	// secret into a banner, in the clear, before any prompt existed — the exact
	// failure a PAM must not have.
	first := make(chan string, 1)
	go func() {
		_, _ = far.Write([]byte("WARNING: do not share your password with anyone.\r\n"))
		time.Sleep(150 * time.Millisecond)
		_, _ = far.Write([]byte("Password: "))
		p, _ := readLine(far)
		_, _ = far.Write([]byte("\r\nRouter>"))
		first <- p
	}()

	if _, err := g.login(c, pwCred("", "hunter2"), time.Now().Add(3*time.Second)); err != nil {
		t.Fatalf("login: %v", err)
	}
	// The secret must arrive exactly once, at the real prompt.
	if p := <-first; p != "hunter2" {
		t.Errorf("device received %q at the prompt, want hunter2", p)
	}
}

func TestLoginFailsWhenTheDeviceNeverPrompts(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	// A terminal server that accepts TCP and says nothing. Better a clear error
	// on Connect than a black terminal the operator cannot type into.
	go func() { _, _ = far.Write([]byte("\r\n")) }()

	_, err := g.login(c, pwCred("u", "p"), time.Now().Add(400*time.Millisecond))
	if !errors.Is(err, access.ErrCredentialUnusable) {
		t.Fatalf("err = %v, want ErrCredentialUnusable", err)
	}
}

func TestLoginFailsWhenAUsernameIsNeededButNotStored(t *testing.T) {
	c, far := pipeConn(t)
	g := testGateway()

	go func() { _, _ = far.Write([]byte("\r\nUsername: ")) }()

	_, err := g.login(c, pwCred("", "p"), time.Now().Add(2*time.Second))
	if !errors.Is(err, access.ErrCredentialUnusable) {
		t.Fatalf("err = %v, want ErrCredentialUnusable", err)
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("err = %q, want it to say the credential needs a username", err)
	}
}

func TestRedactKeepsTheSecretOutOfTheTranscript(t *testing.T) {
	// Echo is negotiated, and some gear echoes at a password prompt anyway. The
	// transcript is handed to auditors; the vaulted secret must not be in it.
	got := redact([]byte("Password: hunter2\r\nRouter>"), "hunter2")
	if strings.Contains(string(got), "hunter2") {
		t.Errorf("redact left the secret in the transcript: %q", got)
	}
	if !strings.Contains(string(got), "[redacted]") {
		t.Errorf("redact = %q, want the removal to be visible", got)
	}
}

func TestRedactOfAnEmptySecretIsANoop(t *testing.T) {
	// A break-glass session has no secret. Replacing the empty string would
	// otherwise splice [redacted] between every byte of the transcript.
	in := "Router>show version\r\n"
	if got := string(redact([]byte(in), "")); got != in {
		t.Errorf("redact(%q, \"\") = %q, want it unchanged", in, got)
	}
}

// A device that echoes the password one character at a time, with carriage
// returns or NULs between them, used to defeat redaction entirely: ReplaceAll
// looks for a contiguous match and there is not one. The vaulted password then
// went into the transcript an auditor reads.
func TestRedactCatchesInterleavedEcho(t *testing.T) {
	const secret = "hunter2"
	cases := []struct {
		name string
		in   string
	}{
		{"contiguous", "login: admin\r\nPassword: " + secret + "\r\n#"},
		{"cr between characters", "Password: h\ru\rn\rt\re\rr\r2\r\n#"},
		{"nul between characters", "Password: h\x00u\x00n\x00t\x00e\x00r\x002\r\n#"},
		{"mixed filler", "Password: h\r\x00u\nn\x00t\re\x00r\r2\r\n#"},
		{"backspace echo", "Password: h\x08u\x08n\x08t\x08e\x08r\x082\r\n#"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := string(redact([]byte(c.in), secret))
			if strings.Contains(got, secret) {
				t.Fatalf("secret survived redaction: %q", got)
			}
			// And the characters must not survive spread out either.
			squeezed := strings.NewReplacer("\r", "", "\n", "", "\x00", "", "\x08", "").Replace(got)
			if strings.Contains(squeezed, secret) {
				t.Fatalf("secret survived once filler was removed: %q", got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Errorf("no redaction marker in %q", got)
			}
		})
	}
}

// Redaction must not eat output that merely starts with the same byte, or the
// transcript stops being a faithful record of the session.
func TestRedactLeavesOtherOutputAlone(t *testing.T) {
	const secret = "hunter2"
	in := "hostname core-sw-1\r\nhelp\r\nh\r\n#"
	if got := string(redact([]byte(in), secret)); got != in {
		t.Fatalf("redact altered unrelated output:\n got %q\nwant %q", got, in)
	}

	// An empty secret is a no-op, not a crash.
	if got := string(redact([]byte(in), "")); got != in {
		t.Errorf("empty secret changed the output: %q", got)
	}
}
