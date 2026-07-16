package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

type fixedLookup struct{ ep access.Endpoint }

func (f fixedLookup) Endpoint(context.Context, access.Scope, uuid.UUID) (access.Endpoint, error) {
	return f.ep, nil
}

type fixedCreds struct{ cred access.Credential }

func (f fixedCreds) Resolve(context.Context, *access.Session) (access.Credential, error) {
	return f.cred, nil
}
func (f fixedCreds) HasCredential(context.Context, access.Scope, uuid.UUID) (bool, error) {
	return true, nil
}

func webSession() *access.Session {
	return &access.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
		Protocol: access.ProtocolHTTPS,
	}
}

func webEndpoint() access.Endpoint {
	return access.Endpoint{
		Protocol: access.ProtocolHTTPS, Host: "10.0.0.1", Port: 443,
		BaseURL: "https://10.0.0.1", VerifyTLS: false,
	}
}

// Form fill needs a browser to type into the page. This gateway only rewrites
// HTTP, so applying a form credential would mean sending the secret to the
// operator's browser — the one thing GuardRail exists to prevent.
//
// It used to just fall through the injection switch: the request went upstream
// with no credential, the device answered with its own login page, and the
// operator sat looking at a login form holding a password they were deliberately
// never told, while the console still showed the credential as bound. Refusing is
// the only honest option.
func TestEstablishRefusesFormInjection(t *testing.T) {
	g := NewHTTPGateway(fixedLookup{ep: webEndpoint()}, nil, nil, "test")
	creds := fixedCreds{cred: access.Credential{
		Username: "admin", Secret: "s3cret", Injection: "form",
	}}

	_, err := g.Establish(context.Background(), webSession(), creds)
	if !errors.Is(err, access.ErrInjectionUnsupported) {
		t.Fatalf("Establish(form) error = %v, want ErrInjectionUnsupported", err)
	}
}

// The injections this gateway CAN apply server-side must still work.
func TestEstablishAcceptsHeaderInjections(t *testing.T) {
	for _, inj := range []string{"basic", "header", "none"} {
		g := NewHTTPGateway(fixedLookup{ep: webEndpoint()}, nil, nil, "test")
		creds := fixedCreds{cred: access.Credential{
			Username: "admin", Secret: "s3cret", Injection: inj,
		}}
		if _, err := g.Establish(context.Background(), webSession(), creds); err != nil {
			t.Errorf("Establish(%s): %v", inj, err)
		}
	}
}
