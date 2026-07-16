package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// OIDCTransaction carries the per-login CSRF/PKCE material the caller must stash
// (in a signed cookie) between the redirect and the callback.
type OIDCTransaction struct {
	AuthURL      string
	State        string
	Nonce        string
	CodeVerifier string
}

// oidcEnabled / ldapEnabled report whether a provider and a target org are wired.
func (s *Service) oidcEnabled() bool { return s.oidc != nil && s.fedOrgID != (iam.ID{}) }
func (s *Service) ldapEnabled() bool { return s.ldap != nil && s.fedOrgID != (iam.ID{}) }

// OIDCEnabled reports whether OIDC login is available (for capability discovery).
func (s *Service) OIDCEnabled() bool { return s.oidcEnabled() }

// LDAPEnabled reports whether LDAP login is available.
func (s *Service) LDAPEnabled() bool { return s.ldapEnabled() }

// BeginOIDCLogin creates PKCE + state/nonce and returns the authorization URL.
func (s *Service) BeginOIDCLogin(ctx context.Context) (*OIDCTransaction, error) {
	if !s.oidcEnabled() {
		return nil, iam.ErrNotFound
	}
	state, err := randToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randToken()
	if err != nil {
		return nil, err
	}
	verifier, err := randToken()
	if err != nil {
		return nil, err
	}
	challenge := pkceChallenge(verifier)
	url := s.oidc.AuthCodeURL(state, nonce, challenge)
	if url == "" {
		return nil, fmt.Errorf("iam: oidc provider unavailable")
	}
	return &OIDCTransaction{AuthURL: url, State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// CompleteOIDCLogin exchanges the code and provisions/authenticates the user.
func (s *Service) CompleteOIDCLogin(ctx context.Context, code, codeVerifier, nonce string, meta ReqMeta) (*TokenPair, error) {
	if !s.oidcEnabled() {
		return nil, iam.ErrNotFound
	}
	ext, err := s.oidc.Exchange(ctx, code, codeVerifier, nonce)
	if err != nil {
		s.record(ctx, audit.Event{Action: "auth.oidc", Category: audit.CategoryAuth,
			IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultFailure,
			Detail: map[string]any{"error": err.Error()}})
		return nil, iam.ErrInvalidCredentials
	}
	return s.completeFederatedLogin(ctx, ext, meta)
}

// LoginWithLDAP binds against the directory and provisions/authenticates.
func (s *Service) LoginWithLDAP(ctx context.Context, username, password string, meta ReqMeta) (*TokenPair, error) {
	if !s.ldapEnabled() {
		return nil, iam.ErrNotFound
	}
	throttleKey := "ldap:" + meta.IP + ":" + username
	if s.throttle != nil {
		if ok, _, e := s.throttle.Allow(ctx, throttleKey); e == nil && !ok {
			return nil, ErrThrottled
		}
	}
	ext, err := s.ldap.Authenticate(ctx, username, password)
	if err != nil {
		if s.throttle != nil {
			_ = s.throttle.Fail(ctx, throttleKey)
		}
		s.record(ctx, audit.Event{Action: "auth.ldap", Category: audit.CategoryAuth,
			ActorEmail: username, IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultFailure})
		return nil, iam.ErrInvalidCredentials
	}
	if s.throttle != nil {
		_ = s.throttle.Reset(ctx, throttleKey)
	}
	return s.completeFederatedLogin(ctx, ext, meta)
}

// completeFederatedLogin links the external identity to a local user in the
// federation org — provisioning one just-in-time on first sign-in — and issues
// tokens. New federated users start with no roles; an admin grants access.
func (s *Service) completeFederatedLogin(ctx context.Context, ext *iam.ExternalIdentity, meta ReqMeta) (*TokenPair, error) {
	if ext == nil || ext.Email == "" {
		return nil, iam.ErrInvalidCredentials
	}
	orgID := s.fedOrgID
	email := iam.NewEmail(ext.Email)

	user, err := s.users.GetByEmailInOrg(ctx, orgID, email)
	if errors.Is(err, iam.ErrNotFound) {
		user = &iam.User{
			ID: iam.NewID(), OrganizationID: orgID, Email: email, Username: ext.Username,
			AuthProvider: iam.AuthProvider(ext.Provider), Status: "active",
		}
		if ce := s.users.Create(ctx, iam.TenantScope{OrganizationID: orgID, IsSuperAdmin: true}, user); ce != nil {
			return nil, ce
		}
		s.record(ctx, audit.Event{OrganizationID: &orgID, Action: "user.provision",
			Category: audit.CategoryAuth, ActorEmail: email.String(), IP: meta.IP, UserAgent: meta.UserAgent,
			Result: audit.ResultSuccess, Detail: map[string]any{"provider": ext.Provider}})
	} else if err != nil {
		return nil, err
	}

	if user.Status != "active" {
		return nil, iam.ErrAccountInactive
	}

	pair, err := s.issueTokens(ctx, user, meta, iam.NewID())
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &orgID, Action: "auth." + ext.Provider,
		Category: audit.CategoryAuth, ActorID: &user.ID, ActorEmail: user.Email.String(),
		IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultSuccess})
	return pair, nil
}

// randToken returns a URL-safe 256-bit random token.
func randToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("iam: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceChallenge returns the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
