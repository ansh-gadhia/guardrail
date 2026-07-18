package telnetgw

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// InjectPassword is the only injection method telnet understands. It mirrors the
// vault's stored value; the HTTP-shaped methods (form/basic/header) and the SSH
// ones are meaningless at a login prompt and are refused rather than reinterpreted.
const InjectPassword = "password"

// Telnet has no authentication of its own. There is no handshake to fail and no
// status code to read: the device prints a prompt and waits for someone to type.
// So these regexes ARE the authentication — if none matches, nothing is typed
// and the operator gets a login prompt they cannot answer, because the whole
// point of a PAM is that they never learn the credential.
//
// Anchored at end-of-input because a prompt is the last thing on the wire when
// the device stops to wait. Matching unanchored would fire on the word
// "password" in a banner — and MOTD banners on network gear are full of it.
var (
	userPrompt = regexp.MustCompile(`(?i)(?:user\s?name|login|user)\s*:\s*$`)
	passPrompt = regexp.MustCompile(`(?i)pass(?:word|code|phrase)?\s*:\s*$`)

	// A shell prompt is how a device says "you are in". Cisco IOS ends at ">"
	// (user EXEC) or "#" (privileged); a Linux-ish box ends at "$".
	shellPrompt = regexp.MustCompile(`(?m)[>#$]\s*$`)

	// What rejection looks like. IOS says "% Login invalid" or re-prompts;
	// others vary. This only has to be good enough to turn a hang into an error.
	authRejected = regexp.MustCompile(`(?i)(login invalid|authentication failed|access denied|bad password|incorrect|% *bad|% *login|too many)`)
)

// loginWindow bounds how much recent output the prompt regexes see. A prompt is
// short and the anchors are at the end, so a wide window only costs time.
const loginWindow = 512

// login types the vaulted credential at the device's own prompts and returns
// everything the device printed while it happened.
//
// It runs during Establish, synchronously, for the same reason the SSH gateway
// authenticates there: a bad credential must fail the Connect request, where the
// operator sees a real error, rather than opening a terminal that sits at a
// prompt forever with no way to answer it.
//
// The returned banner is replayed to the console so the operator sees the login
// exactly as it happened, and is recorded so the transcript starts where the
// session did.
func (g *Gateway) login(c *conn, cred access.Credential, deadline time.Time) ([]byte, error) {
	if cred.Injection != InjectPassword {
		// Wrapped in the domain error so the API answers 422 with this sentence
		// rather than a 500 that tells the operator nothing. This is the commonest
		// first-time mistake there is: binding a web credential to a CLI device.
		return nil, fmt.Errorf("%w: this device speaks telnet, but its credential is set to %q. Re-save the credential using %q",
			access.ErrCredentialUnusable, cred.Injection, InjectPassword)
	}

	var (
		banner []byte // everything the device printed, for the console + transcript
		window []byte // output since our last keystroke, for prompt matching
		sentU  bool
		sentP  bool
		buf    = make([]byte, 4<<10)
	)

	for {
		if !time.Now().Before(deadline) {
			// Out of time. If the credential went in, believe it worked: a device
			// that is simply slow or quiet after login is far commoner than one
			// that accepted a password and then said nothing at all, and refusing
			// a working session is the worse error.
			if sentP {
				return banner, nil
			}
			return nil, fmt.Errorf("%w: no login prompt from the device within %s",
				access.ErrCredentialUnusable, g.cfg.LoginTimeout)
		}
		_ = c.raw.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if n > 0 {
			banner = append(banner, buf[:n]...)
			window = append(window, buf[:n]...)
			if len(window) > loginWindow {
				window = window[len(window)-loginWindow:]
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if sentP {
					return banner, nil
				}
				return nil, fmt.Errorf("%w: no login prompt from the device within %s",
					access.ErrCredentialUnusable, g.cfg.LoginTimeout)
			}
			// The device hung up mid-login. On IOS that is what "too many login
			// attempts" and a full vty pool look like.
			return nil, fmt.Errorf("%w: the device closed the connection during login", access.ErrCredentialUnusable)
		}

		text := string(window)

		if !sentP && passPrompt.MatchString(text) {
			if err := typeLine(c, cred.Secret); err != nil {
				return nil, err
			}
			sentP = true
			// Reset the window so the prompt we just answered cannot match again
			// and read as a rejection. Only output that arrives AFTER a keystroke
			// says anything about whether that keystroke worked.
			window = window[:0]
			continue
		}
		if !sentU && userPrompt.MatchString(text) {
			if cred.Username == "" {
				return nil, fmt.Errorf("%w: the device is asking for a username, but this credential has none. Re-save it with the username the device expects",
					access.ErrCredentialUnusable)
			}
			if err := typeLine(c, cred.Username); err != nil {
				return nil, err
			}
			sentU = true
			window = window[:0]
			continue
		}
		if sentP {
			// Everything from here is post-password output: it is the device's
			// verdict.
			if authRejected.MatchString(text) || passPrompt.MatchString(text) || userPrompt.MatchString(text) {
				return nil, fmt.Errorf("%w: the device rejected the stored credential", access.ErrCredentialUnusable)
			}
			if shellPrompt.MatchString(text) {
				return banner, nil
			}
		}
	}
}

// typeLine sends one line as a person would, terminated CR LF.
//
// CR LF, not LF: RFC 854 says a bare CR must be followed by LF or NUL, and IOS
// is one of the stacks that means it — a lone \n can be swallowed, leaving the
// password sitting unsent at the prompt and the login timing out for no visible
// reason.
func typeLine(c *conn, s string) error {
	_, err := c.Write([]byte(s + "\r\n"))
	return err
}

// redact removes the injected secret from captured output.
//
// The recorder only ever sees device output, so in the normal case a password is
// never in it: the device does not echo at a password prompt. But "normal case"
// is not a guarantee — echo is negotiated, some gear echoes anyway, and a
// mistyped credential can land in a field that does echo. A PAM that leaks the
// vaulted password into the very transcript it hands to auditors would be worse
// than one that never recorded at all, so this is belt and braces.
func redact(b []byte, secret string) []byte {
	if secret == "" || len(b) == 0 {
		return b
	}
	return bytes.ReplaceAll(b, []byte(secret), []byte("[redacted]"))
}

// trimBanner keeps the tail of the login output for replay to a viewer, so a
// device whose MOTD is a `show tech` wall does not push the actual prompt off
// the operator's screen.
func trimBanner(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	cut := b[len(b)-max:]
	// Start at a line boundary so the replay does not open mid-escape-sequence.
	if i := bytes.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return cut
}
