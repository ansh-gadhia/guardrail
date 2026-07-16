// Package iam is the IAM application layer: use cases that orchestrate domain
// aggregates and ports (repositories, hasher, token issuer, throttle, audit). It
// depends only on the domain — never on Gin, pgx, or Redis directly.
package iam

import (
	"context"
	"time"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Throttle is a brute-force guard (per ip/email) backed by a fast store.
type Throttle interface {
	// Allow reports whether an attempt for key may proceed; if not, it returns
	// the retry-after duration.
	Allow(ctx context.Context, key string) (bool, time.Duration, error)
	// Fail records a failed attempt for key.
	Fail(ctx context.Context, key string) error
	// Reset clears the counter for key after success.
	Reset(ctx context.Context, key string) error
}

// Config holds tunable IAM policy.
type Config struct {
	MaxLoginFailures int           // account lockout threshold
	LockoutDuration  time.Duration // how long an account stays locked
	RefreshTTL       time.Duration // refresh-token lifetime
}

// DefaultConfig returns production-sensible defaults.
func DefaultConfig() Config {
	return Config{MaxLoginFailures: 5, LockoutDuration: 15 * time.Minute, RefreshTTL: 720 * time.Hour}
}

// Service implements the IAM use cases.
type Service struct {
	users    iam.UserRepository
	orgs     iam.OrganizationRepository
	roles    iam.RoleRepository
	sessions iam.AuthSessionRepository
	hasher   iam.PasswordHasher
	tokens   iam.TokenIssuer
	refresh  iam.RefreshTokenGenerator
	audit    audit.Recorder
	throttle Throttle
	clock    iam.Clock
	cfg      Config

	// MFA collaborators are optional; when mfa is nil, MFA is disabled globally.
	mfa       iam.MFARepository
	totp      iam.TOTP
	cipher    iam.Cipher
	mfaChal   iam.MFAChallenger
	mfaIssuer string // issuer label embedded in provisioning URIs

	// Federation collaborators are optional; providers are enabled only when both
	// the provider and a target provisioning org (fedOrgID) are configured.
	oidc     iam.OIDCAuthenticator
	ldap     iam.PasswordAuthenticator
	fedOrgID iam.ID

	// decoyHash is verified against for unknown users to blunt user-enumeration
	// timing side channels. Computed once at construction.
	decoyHash string
}

// Deps bundles the collaborators for NewService.
type Deps struct {
	Users    iam.UserRepository
	Orgs     iam.OrganizationRepository
	Roles    iam.RoleRepository
	Sessions iam.AuthSessionRepository
	Hasher   iam.PasswordHasher
	Tokens   iam.TokenIssuer
	Refresh  iam.RefreshTokenGenerator
	Audit    audit.Recorder
	Throttle Throttle
	Clock    iam.Clock
	Config   Config

	// Optional MFA wiring. Leave nil to disable multi-factor authentication.
	MFA       iam.MFARepository
	TOTP      iam.TOTP
	Cipher    iam.Cipher
	MFAChal   iam.MFAChallenger
	MFAIssuer string

	// Optional federation wiring. Providers activate only when FederationOrgID is
	// also set (the org new federated users are provisioned into).
	OIDC            iam.OIDCAuthenticator
	LDAP            iam.PasswordAuthenticator
	FederationOrgID iam.ID
}

// NewService constructs the IAM service, filling in a system clock if absent.
func NewService(d Deps) *Service {
	clock := d.Clock
	if clock == nil {
		clock = iam.SystemClock{}
	}
	issuer := d.MFAIssuer
	if issuer == "" {
		issuer = "GuardRail"
	}
	s := &Service{
		users: d.Users, orgs: d.Orgs, roles: d.Roles, sessions: d.Sessions,
		hasher: d.Hasher, tokens: d.Tokens, refresh: d.Refresh, audit: d.Audit,
		throttle: d.Throttle, clock: clock, cfg: d.Config,
		mfa: d.MFA, totp: d.TOTP, cipher: d.Cipher, mfaChal: d.MFAChal, mfaIssuer: issuer,
		oidc: d.OIDC, ldap: d.LDAP, fedOrgID: d.FederationOrgID,
	}
	// Precompute a decoy hash so unknown-user logins still perform a real verify.
	if h, err := d.Hasher.Hash("guardrail-decoy-" + iam.NewID().String()); err == nil {
		s.decoyHash = h
	}
	return s
}

// record is a best-effort audit helper; audit failures never block the caller
// but are surfaced via the returned error for logging by the delivery layer.
func (s *Service) record(ctx context.Context, e audit.Event) {
	if s.audit == nil {
		return
	}
	if e.ID == (iam.ID{}) {
		e.ID = iam.NewID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = s.clock.Now()
	}
	_ = s.audit.Record(ctx, e)
}
