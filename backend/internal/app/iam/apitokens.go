package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// touchInterval throttles the last-used stamp. Writing a row on every request a
// dashboard makes would turn a read-only status poll into a write amplifier on
// the busiest table nobody reads; a minute's resolution answers the only
// question the column exists for — is anything still using this token.
const touchInterval = time.Minute

// NewAPITokenResult carries the one and only look at a freshly minted token.
type NewAPITokenResult struct {
	Token iam.APIToken
	// Raw is the credential. It is returned here, once, and never stored — only
	// its hash is. A token the server could show you again is a token an
	// attacker with a database copy already has.
	Raw string
}

// CreateAPIToken issues a machine credential.
//
// Restricted to super admins. Issuing a credential that authenticates with no
// login, carries no expiry by default, and will sit in a config file on some
// monitoring box is not an ordinary administrative act — and the permission
// catalogue has no key for it, so inventing one that some role already held
// would quietly widen that role.
func (s *Service) CreateAPIToken(
	ctx context.Context, actor iam.Claims, name string, scopes []string, expiresAt *time.Time, meta ReqMeta,
) (*NewAPITokenResult, error) {
	if s.apiTokens == nil {
		return nil, iam.ErrNotFound
	}
	if !actor.IsSuperAdmin {
		return nil, iam.ErrPermissionDenied
	}
	if name == "" {
		return nil, fmt.Errorf("%w: a token needs a name", iam.ErrInvalidInput)
	}
	// An already-expired token is almost certainly a timezone mistake, and it
	// would fail at the far end with "invalid token" hours later.
	if expiresAt != nil && !expiresAt.After(s.clock.Now()) {
		return nil, fmt.Errorf("%w: expiry must be in the future", iam.ErrInvalidInput)
	}
	valid, err := iam.ValidateScopes(scopes)
	if err != nil {
		return nil, err
	}

	raw, hash, prefix, err := iam.NewAPITokenSecret()
	if err != nil {
		return nil, fmt.Errorf("iam: mint token: %w", err)
	}
	issuer := actor.UserID
	tok := &iam.APIToken{
		ID: iam.NewID(), OrganizationID: actor.OrganizationID, Name: name,
		Prefix: prefix, Hash: hash, Scopes: valid, CreatedBy: &issuer, ExpiresAt: expiresAt,
	}
	if err := s.apiTokens.Create(ctx, actor.Scope(), tok); err != nil {
		return nil, err
	}
	// Audited with its scopes: "who gave a machine standing read access to the
	// estate, and what could it see" is the question this row has to answer.
	s.record(ctx, audit.Event{
		OrganizationID: &actor.OrganizationID, Action: "apitoken.create", Category: audit.CategoryAuth,
		ActorID: &actor.UserID, ActorEmail: actor.Email, IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess,
		Detail: map[string]any{"token_id": tok.ID.String(), "name": name, "scopes": valid},
	})
	return &NewAPITokenResult{Token: *tok, Raw: raw}, nil
}

// ListAPITokens returns the organization's tokens. Never the raw values — they
// do not exist anywhere to return.
func (s *Service) ListAPITokens(ctx context.Context, actor iam.Claims) ([]iam.APIToken, error) {
	if s.apiTokens == nil {
		return nil, iam.ErrNotFound
	}
	if !actor.IsSuperAdmin {
		return nil, iam.ErrPermissionDenied
	}
	return s.apiTokens.List(ctx, actor.Scope())
}

// RevokeAPIToken stops a token working, immediately and everywhere.
func (s *Service) RevokeAPIToken(ctx context.Context, actor iam.Claims, id iam.ID, meta ReqMeta) error {
	if s.apiTokens == nil {
		return iam.ErrNotFound
	}
	if !actor.IsSuperAdmin {
		return iam.ErrPermissionDenied
	}
	if err := s.apiTokens.Revoke(ctx, actor.Scope(), id, s.clock.Now()); err != nil {
		return err
	}
	s.record(ctx, audit.Event{
		OrganizationID: &actor.OrganizationID, Action: "apitoken.revoke", Category: audit.CategoryAuth,
		ActorID: &actor.UserID, ActorEmail: actor.Email, IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{"token_id": id.String()},
	})
	return nil
}

// VerifyAPIToken resolves a presented token to a principal.
//
// It is the hot path — every request a machine makes lands here — so it does one
// indexed lookup by hash and, at most once a minute, one small update. It does
// NOT write an audit event per call: that is the whole reason this exists
// instead of logging in, and an events table growing by 2,880 rows a day per
// dashboard is the thing being avoided.
func (s *Service) VerifyAPIToken(ctx context.Context, raw string) (iam.Claims, error) {
	if s.apiTokens == nil {
		return iam.Claims{}, iam.ErrInvalidCredentials
	}
	tok, err := s.apiTokens.FindByHash(ctx, iam.HashAPIToken(raw))
	if err != nil {
		// A token that does not exist and one that was revoked are the same
		// answer to the caller. Distinguishing them tells a prober which of their
		// guesses used to be real.
		if errors.Is(err, iam.ErrNotFound) {
			return iam.Claims{}, iam.ErrInvalidCredentials
		}
		return iam.Claims{}, err
	}
	now := s.clock.Now()
	if !tok.IsUsable(now) {
		return iam.Claims{}, iam.ErrInvalidCredentials
	}
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= touchInterval {
		// Best-effort: failing to record use must not fail the request.
		_ = s.apiTokens.TouchUsed(ctx, tok.ID, now)
	}
	return tok.Claims(), nil
}
