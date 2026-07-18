package guacgw

import (
	"strings"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// A web credential on a desktop device must be refused by name, not handed to
// guacd as a password. If it were, Windows would reject it and the operator
// would be told "wrong password" about a credential whose secret may be
// perfectly correct — for a different device.
func TestCheckCredentialRefusesNonDesktopMethods(t *testing.T) {
	for _, m := range []string{"basic", "form", "header", "ssh-password", "ssh-key", "none", ""} {
		t.Run(m, func(t *testing.T) {
			err := checkCredential(access.Credential{Injection: m, Secret: "s3cret"}, access.ProtocolRDP)
			if err == nil {
				t.Fatalf("injection %q was accepted for RDP; its secret would go on the wire as a password", m)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the error echoes the secret: %v", err)
			}
			// The operator has to know what to do about it.
			if !strings.Contains(err.Error(), InjectPassword) {
				t.Errorf("the error does not name the method to use: %v", err)
			}
		})
	}
}

func TestCheckCredentialAcceptsPassword(t *testing.T) {
	for _, p := range []access.Protocol{access.ProtocolRDP, access.ProtocolVNC} {
		if err := checkCredential(access.Credential{Injection: InjectPassword, Username: "W11"}, p); err != nil {
			t.Errorf("%s rejected the only method it can use: %v", p, err)
		}
	}
}

// A credential with no username is refused for the protocols that need one,
// because the alternative is silent and much worse than an error: guacd sends an
// empty username, RDP has nobody to authenticate as, and Windows paints its own
// login screen pre-filled with the last account to use the machine. The operator
// signs in there as somebody else entirely, with no credential injected, while
// the audit trail records that a credential was resolved and used.
func TestCheckCredentialRefusesEmptyUsername(t *testing.T) {
	for _, p := range []access.Protocol{access.ProtocolRDP} {
		t.Run(string(p), func(t *testing.T) {
			err := checkCredential(access.Credential{Injection: InjectPassword, Secret: "s3cret"}, p)
			if err == nil {
				t.Fatalf("%s accepted a credential with no username; the device would show its own login page", p)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the error echoes the secret: %v", err)
			}
			if !strings.Contains(err.Error(), "username") {
				t.Errorf("the error does not say what is missing: %v", err)
			}
		})
	}
}

// VNC is the exception and must stay one: its authentication is a password and
// nothing else, so there is no username to demand. Requiring one here would
// refuse every correctly configured VNC device on the estate.
func TestCheckCredentialAllowsEmptyUsernameForVNC(t *testing.T) {
	if err := checkCredential(access.Credential{Injection: InjectPassword, Secret: "s3cret"}, access.ProtocolVNC); err != nil {
		t.Errorf("VNC rejected a password-only credential, which is the only shape VNC auth has: %v", err)
	}
}

// Break-glass omits the credential params rather than sending them empty, so the
// device presents its own login instead of failing against a blank username.
func TestParamsOmitsEmptyCredential(t *testing.T) {
	g := NewGateway(access.ProtocolRDP, Config{}, Deps{})
	p := g.params(access.Endpoint{Host: "10.0.0.5"}, access.Credential{}, 3389, "")
	for _, k := range []string{"username", "password"} {
		if _, ok := p[k]; ok {
			t.Errorf("%q was sent to guacd under break-glass; it must be omitted, not empty", k)
		}
	}
}

// Break-glass negotiates, it does not pin. Forcing legacy "rdp" security made a
// current Windows refuse outright ("wrong security type?"); "any" reaches any host
// that permits a non-NLA login and lets the rest fail honestly on their own NLA
// policy. Either way the security value is the same as the credentialled path.
func TestParamsNegotiatesUnderBreakGlass(t *testing.T) {
	g := NewGateway(access.ProtocolRDP, Config{}, Deps{})
	if got := g.params(access.Endpoint{Host: "10.0.0.5"}, access.Credential{}, 3389, "")["security"]; got != "any" {
		t.Errorf("security = %q under break-glass; forcing a mode is what made hosts refuse the connection", got)
	}
}

func TestParamsNegotiatesWithACredential(t *testing.T) {
	g := NewGateway(access.ProtocolRDP, Config{}, Deps{})
	p := g.params(access.Endpoint{Host: "10.0.0.5"}, access.Credential{Username: "admin", Secret: "pw"}, 3389, "")
	if p["security"] != "any" {
		t.Errorf("security = %q with a credential, want any", p["security"])
	}
}

// Break-glass cannot verify a cert it has not authenticated past, so it ignores
// it; a credentialled session honours the device's own VerifyTLS choice.
func TestParamsIgnoresCertUnderBreakGlassOnly(t *testing.T) {
	g := NewGateway(access.ProtocolRDP, Config{}, Deps{})
	bg := g.params(access.Endpoint{Host: "10.0.0.5", VerifyTLS: true}, access.Credential{}, 3389, "")
	if bg["ignore-cert"] != "true" {
		t.Errorf("ignore-cert = %q under break-glass, want true — a strict check rejects the logon host's self-signed cert", bg["ignore-cert"])
	}
	cred := g.params(access.Endpoint{Host: "10.0.0.5", VerifyTLS: true}, access.Credential{Username: "a", Secret: "p"}, 3389, "")
	if cred["ignore-cert"] != "false" {
		t.Errorf("ignore-cert = %q with a credential and VerifyTLS on, want false", cred["ignore-cert"])
	}
}

func TestParamsCarriesCredential(t *testing.T) {
	g := NewGateway(access.ProtocolRDP, Config{}, Deps{})
	p := g.params(access.Endpoint{Host: "10.0.0.5"}, access.Credential{Username: "admin", Secret: "pw"}, 3389, "")
	if p["username"] != "admin" || p["password"] != "pw" {
		t.Errorf("the credential did not reach guacd: username=%q password set=%v", p["username"], p["password"] != "")
	}
}
