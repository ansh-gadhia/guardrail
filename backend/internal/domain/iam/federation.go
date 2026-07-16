package iam

import "context"

// ExternalIdentity is a verified identity asserted by a federated identity
// provider (OIDC, LDAP/AD, or SAML). Subject is the provider's stable, opaque
// identifier for the principal and is what the local user is linked by.
type ExternalIdentity struct {
	Provider    string // "oidc" | "ldap" | "saml"
	Subject     string // stable IdP subject / DN
	Email       string
	Username    string
	DisplayName string
}

// OIDCAuthenticator is the redirect-based Authorization Code + PKCE relying
// party. The handler drives the browser redirect with AuthCodeURL, then trades
// the returned code (plus the stored PKCE verifier and nonce) via Exchange.
type OIDCAuthenticator interface {
	AuthCodeURL(state, nonce, codeChallenge string) string
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (*ExternalIdentity, error)
}

// PasswordAuthenticator verifies a username/password directly against an
// external directory (LDAP/AD bind) and returns the resolved identity.
type PasswordAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (*ExternalIdentity, error)
}
