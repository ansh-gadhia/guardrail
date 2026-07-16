package assets

import (
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// schemeOrDefault previously mapped everything that was not "http" to "https".
// A device registered as "ssh" was stored as an HTTPS device and then brokered
// to the reverse proxy, which injects the vaulted credential as an Authorization
// header — sending the device password to port 22 in the clear. Silently
// rewriting a protocol is never acceptable; refusing is.
func TestSchemeOrDefaultRejectsUnknown(t *testing.T) {
	// "telnet" is brokered now, so it belongs in the accepted set, not here.
	for _, in := range []string{"ftp", "TELNET", "HTTPS", "sftp", "gopher", "ssh ", "https://"} {
		got, err := schemeOrDefault(in)
		if err == nil {
			t.Errorf("schemeOrDefault(%q) = %q with no error; unknown protocols must be refused, not coerced", in, got)
			continue
		}
		if !errors.Is(err, assets.ErrInvalid) {
			t.Errorf("schemeOrDefault(%q) error = %v, want it to wrap assets.ErrInvalid so the API answers 400", in, err)
		}
	}
}

// Saying nothing still means https — the common case, and the previous default.
func TestSchemeOrDefaultEmptyIsHTTPS(t *testing.T) {
	got, err := schemeOrDefault("")
	if err != nil {
		t.Fatalf("schemeOrDefault(\"\"): %v", err)
	}
	if got != "https" {
		t.Errorf("schemeOrDefault(\"\") = %q, want https", got)
	}
}

func TestSchemeOrDefaultAcceptsKnown(t *testing.T) {
	for _, in := range assets.Schemes() {
		got, err := schemeOrDefault(in)
		if err != nil {
			t.Errorf("schemeOrDefault(%q): %v", in, err)
			continue
		}
		if got != in {
			t.Errorf("schemeOrDefault(%q) = %q; a valid protocol must survive unchanged", in, got)
		}
	}
}

// The port follows the protocol when unspecified, so picking SSH does not leave
// a device pointed at 443.
func TestPortOrDefaultFollowsScheme(t *testing.T) {
	for scheme, want := range map[string]int{
		"https": 443, "http": 80, "ssh": 22, "rdp": 3389, "vnc": 5900,
	} {
		if got := portOrDefault(0, scheme); got != want {
			t.Errorf("portOrDefault(0, %q) = %d, want %d", scheme, got, want)
		}
	}
}

// An explicit port always wins: plenty of SSH listens on 2222.
func TestPortOrDefaultKeepsExplicitPort(t *testing.T) {
	if got := portOrDefault(2222, "ssh"); got != 2222 {
		t.Errorf("portOrDefault(2222, ssh) = %d, want 2222 — an explicit port must not be overridden", got)
	}
}
