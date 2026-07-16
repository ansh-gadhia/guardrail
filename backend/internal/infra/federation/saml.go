package federation

import (
	"context"
	"errors"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ErrSAMLNotImplemented is returned by the SAML stub until the binding is built.
var ErrSAMLNotImplemented = errors.New("federation: SAML is not yet implemented")

// SAMLConfig configures a SAML 2.0 service provider (Web Browser SSO profile).
// The fields mirror what a real implementation (HTTP-Redirect/POST bindings,
// metadata exchange, assertion signature validation) will consume.
type SAMLConfig struct {
	IDPMetadataURL string // IdP metadata (endpoints + signing certs)
	SPEntityID     string // this service provider's entity id
	ACSURL         string // assertion consumer service (callback) URL
	Certificate    string // SP signing/encryption certificate (PEM)
	PrivateKey     string // SP private key (PEM)
}

// SAMLProvider is a placeholder service provider. It implements the identity-
// resolution shape so it can be slotted in later without touching the IAM
// application layer; every call currently reports ErrSAMLNotImplemented.
//
// Roadmap: parse IdP metadata, generate signed AuthnRequests (HTTP-Redirect
// binding), consume signed assertions at the ACS (HTTP-POST binding), validate
// signatures + conditions, and map attributes to an iam.ExternalIdentity.
type SAMLProvider struct{ cfg SAMLConfig }

// NewSAMLProvider constructs the stub provider.
func NewSAMLProvider(cfg SAMLConfig) *SAMLProvider { return &SAMLProvider{cfg: cfg} }

// AuthnRequestURL will build the IdP redirect URL for a SAML AuthnRequest.
func (p *SAMLProvider) AuthnRequestURL(relayState string) (string, error) {
	return "", ErrSAMLNotImplemented
}

// ConsumeAssertion will validate a POSTed SAML assertion and return the identity.
func (p *SAMLProvider) ConsumeAssertion(ctx context.Context, samlResponse string) (*iam.ExternalIdentity, error) {
	return nil, ErrSAMLNotImplemented
}
