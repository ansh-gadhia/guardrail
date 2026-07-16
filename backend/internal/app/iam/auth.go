package iam

import (
	"context"
	"errors"
	"time"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ErrThrottled is returned when too many attempts occur for a key.
var ErrThrottled = errors.New("iam: too many attempts")

// Login authenticates a user with email + password and issues a token pair.
// Brute-force is defended at two levels: a per-ip/email throttle and per-account
// failure counting with lockout. Timing is kept roughly constant by always
// running a password verification even when the user is unknown.
func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	now := s.clock.Now()
	email := iam.NewEmail(in.Email)
	throttleKey := "login:" + in.Meta.IP + ":" + email.String()

	if s.throttle != nil {
		ok, _, err := s.throttle.Allow(ctx, throttleKey)
		if err == nil && !ok {
			s.record(ctx, audit.Event{Action: "auth.login", Category: audit.CategoryAuth,
				ActorEmail: email.String(), IP: in.Meta.IP, UserAgent: in.Meta.UserAgent,
				Result: audit.ResultDenied, Detail: map[string]any{"reason": "throttled"}})
			return nil, ErrThrottled
		}
	}

	user, err := s.resolveLoginUser(ctx, email, in.Organization)
	if err != nil && !errors.Is(err, iam.ErrNotFound) && !errors.Is(err, iam.ErrInvalidCredentials) {
		return nil, err // ambiguous email or infra error
	}

	// Always perform a verification to reduce user-enumeration timing signals.
	hash := s.decoyHash
	if user != nil && user.PasswordHash != "" {
		hash = user.PasswordHash
	}
	pwOK, _ := s.hasher.Verify(in.Password, hash)

	if user == nil || user.AuthProvider != iam.ProviderLocal || user.PasswordHash == "" {
		s.failLogin(ctx, throttleKey, nil, email, in.Meta, "unknown_user")
		return nil, iam.ErrInvalidCredentials
	}
	if user.IsLocked(now) {
		s.record(ctx, s.authEvent(user, in.Meta, audit.ResultDenied, "account_locked"))
		return nil, iam.ErrAccountLocked
	}
	if !pwOK {
		s.failLogin(ctx, throttleKey, user, email, in.Meta, "bad_password")
		return nil, iam.ErrInvalidCredentials
	}
	if user.Status != "active" {
		s.record(ctx, s.authEvent(user, in.Meta, audit.ResultDenied, "inactive"))
		return nil, iam.ErrAccountInactive
	}

	// Success: reset counters, opportunistically upgrade the password hash.
	_ = s.users.RecordLoginSuccess(ctx, user.ID, now)
	if s.throttle != nil {
		_ = s.throttle.Reset(ctx, throttleKey)
	}
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if nh, e := s.hasher.Hash(in.Password); e == nil {
			_ = s.users.UpdatePasswordHash(ctx, user.ID, nh)
		}
	}

	// Second factor: if the user has a confirmed MFA method, stop here and return
	// a short-lived challenge instead of tokens. The client completes with
	// VerifyMFA. Password validity has already been proven at this point.
	if s.mfa != nil {
		if m, e := s.mfa.Get(ctx, user.ID); e == nil && m.Confirmed() {
			challenge, ce := s.mfaChal.Issue(user.ID, now)
			if ce != nil {
				return nil, ce
			}
			s.record(ctx, s.authEvent(user, in.Meta, audit.ResultSuccess, "mfa_challenge"))
			return &TokenPair{MFARequired: true, MFAToken: challenge, Principal: principalFromUser(user)}, nil
		}
	}

	pair, err := s.issueTokens(ctx, user, in.Meta, iam.NewID())
	if err != nil {
		return nil, err
	}
	s.record(ctx, s.authEvent(user, in.Meta, audit.ResultSuccess, ""))
	return pair, nil
}

// resolveLoginUser finds the user to authenticate, using the org slug when given
// and otherwise requiring a globally-unique email.
func (s *Service) resolveLoginUser(ctx context.Context, email iam.Email, orgSlug string) (*iam.User, error) {
	if orgSlug != "" {
		org, err := s.orgs.GetBySlug(ctx, orgSlug)
		if err != nil {
			return nil, iam.ErrInvalidCredentials
		}
		u, err := s.users.GetByEmailInOrg(ctx, org.ID, email)
		if err != nil {
			return nil, iam.ErrInvalidCredentials
		}
		return u, nil
	}
	candidates, err := s.users.GetByEmailGlobal(ctx, email)
	if err != nil {
		return nil, err
	}
	switch len(candidates) {
	case 0:
		return nil, iam.ErrNotFound
	case 1:
		u := candidates[0]
		return &u, nil
	default:
		return nil, iam.ErrEmailAmbiguous
	}
}

// failLogin records a failed attempt, incrementing account + throttle counters
// and locking the account when the threshold is reached.
func (s *Service) failLogin(ctx context.Context, throttleKey string, user *iam.User, email iam.Email, meta ReqMeta, reason string) {
	if s.throttle != nil {
		_ = s.throttle.Fail(ctx, throttleKey)
	}
	if user != nil {
		var lockUntil *time.Time
		if user.FailedLoginCount+1 >= s.cfg.MaxLoginFailures {
			t := s.clock.Now().Add(s.cfg.LockoutDuration)
			lockUntil = &t
		}
		_ = s.users.RecordLoginFailure(ctx, user.ID, lockUntil)
		s.record(ctx, s.authEvent(user, meta, audit.ResultFailure, reason))
		return
	}
	s.record(ctx, audit.Event{Action: "auth.login", Category: audit.CategoryAuth,
		ActorEmail: email.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultFailure, Detail: map[string]any{"reason": reason}})
}

// Refresh rotates a refresh token, detecting reuse of an already-rotated token.
func (s *Service) Refresh(ctx context.Context, rawToken string, meta ReqMeta) (*TokenPair, error) {
	now := s.clock.Now()
	hash := s.refresh.Hash(rawToken)
	sess, err := s.sessions.GetByTokenHash(ctx, hash)
	if err != nil {
		return nil, iam.ErrRefreshInvalid
	}

	// Reuse detection: a presented-but-revoked token means the family is
	// compromised — revoke every session in it and force re-login.
	if sess.RevokedAt != nil {
		_ = s.sessions.RevokeFamily(ctx, sess.FamilyID, now)
		s.record(ctx, audit.Event{Action: "auth.refresh", Category: audit.CategoryAuth,
			ActorID: &sess.UserID, IP: meta.IP, UserAgent: meta.UserAgent,
			Result: audit.ResultFailure, Detail: map[string]any{"reason": "refresh_reuse"}})
		return nil, iam.ErrRefreshReuse
	}
	if !sess.IsUsable(now) {
		return nil, iam.ErrRefreshInvalid
	}

	// Load the user (trusted system read) to refresh the authz snapshot.
	user, err := s.users.GetByID(ctx, iam.TenantScope{IsSuperAdmin: true}, sess.UserID)
	if err != nil {
		return nil, iam.ErrRefreshInvalid
	}

	// Rotate: revoke the presented token, mint a new one in the same family.
	_ = s.sessions.Revoke(ctx, sess.ID, now)
	pair, err := s.issueTokens(ctx, user, meta, sess.FamilyID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &user.OrganizationID, Action: "auth.refresh",
		Category: audit.CategoryAuth, ActorID: &user.ID, ActorEmail: user.Email.String(),
		IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultSuccess})
	return pair, nil
}

// Logout revokes the family of the presented refresh token.
func (s *Service) Logout(ctx context.Context, rawToken string, meta ReqMeta) error {
	sess, err := s.sessions.GetByTokenHash(ctx, s.refresh.Hash(rawToken))
	if err != nil {
		return nil // idempotent: unknown token is a no-op
	}
	_ = s.sessions.RevokeFamily(ctx, sess.FamilyID, s.clock.Now())
	s.record(ctx, audit.Event{Action: "auth.logout", Category: audit.CategoryAuth,
		ActorID: &sess.UserID, IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultSuccess})
	return nil
}

// ChangePassword lets an authenticated local user rotate their own password. It
// verifies the current password, enforces the length policy, re-hashes, and then
// revokes ALL of the user's refresh sessions so any stolen session is killed. To
// keep the caller's browser signed in, it mints and returns a fresh token pair.
func (s *Service) ChangePassword(ctx context.Context, actor iam.Claims, current, next string, meta ReqMeta) (*TokenPair, error) {
	user, err := s.users.GetByID(ctx, actor.Scope(), actor.UserID)
	if err != nil {
		return nil, err
	}
	// Federated (OIDC/LDAP) accounts have no local password to change.
	if user.AuthProvider != iam.ProviderLocal || user.PasswordHash == "" {
		return nil, iam.ErrPasswordUnsupported
	}
	if ok, _ := s.hasher.Verify(current, user.PasswordHash); !ok {
		s.record(ctx, s.pwEvent(user, meta, audit.ResultFailure, "bad_current_password"))
		return nil, iam.ErrInvalidCredentials
	}
	// Reuse is checked before policy: if someone re-types the password they
	// already have, "you can't reuse it" is the useful answer, even when that old
	// password would also fail a policy that has tightened since it was set.
	if next == current {
		return nil, iam.ErrPasswordReuse
	}
	if err := iam.ValidatePassword(next); err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(next)
	if err != nil {
		return nil, err
	}
	if err := s.users.UpdatePasswordHash(ctx, user.ID, hash); err != nil {
		return nil, err
	}
	// Choosing their own password clears the forced-change flag: this is exactly
	// the act the flag was waiting for, whether it happened at first sign-in or
	// later from the console.
	if user.MustChangePassword {
		if err := s.users.SetMustChangePassword(ctx, user.ID, false); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	// Invalidate every existing refresh-token family for this user.
	_ = s.sessions.RevokeAllForUser(ctx, user.ID, now)
	s.record(ctx, s.pwEvent(user, meta, audit.ResultSuccess, ""))
	// Re-issue tokens in a brand-new family so the current session survives.
	return s.issueTokens(ctx, user, meta, iam.NewID())
}

func (s *Service) pwEvent(u *iam.User, meta ReqMeta, result audit.Result, reason string) audit.Event {
	detail := map[string]any{}
	if reason != "" {
		detail["reason"] = reason
	}
	return audit.Event{
		OrganizationID: &u.OrganizationID, Action: "auth.password_change", Category: audit.CategoryAuth,
		ActorID: &u.ID, ActorEmail: u.Email.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: result, Detail: detail,
	}
}

// Me returns the current principal, reloaded from storage within its scope.
func (s *Service) Me(ctx context.Context, claims iam.Claims) (*Principal, error) {
	user, err := s.users.GetByID(ctx, claims.Scope(), claims.UserID)
	if err != nil {
		return nil, err
	}
	p := principalFromUser(user)
	return &p, nil
}

// issueTokens mints an access JWT and a rotated refresh token in the given
// family, persisting the refresh session.
func (s *Service) issueTokens(ctx context.Context, user *iam.User, meta ReqMeta, familyID iam.ID) (*TokenPair, error) {
	now := s.clock.Now()
	access, accessExp, err := s.tokens.Issue(claimsFromUser(user), now)
	if err != nil {
		return nil, err
	}
	rawRefresh, refreshHash, err := s.refresh.Generate()
	if err != nil {
		return nil, err
	}
	refreshExp := now.Add(s.cfg.RefreshTTL)
	sess := &iam.AuthSession{
		ID: iam.NewID(), UserID: user.ID, FamilyID: familyID, RefreshTokenHash: refreshHash,
		UserAgent: meta.UserAgent, IP: meta.IP, ExpiresAt: refreshExp,
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken: access, AccessExpiresAt: accessExp,
		RefreshToken: rawRefresh, RefreshExpiresAt: refreshExp,
		Principal: principalFromUser(user),
	}, nil
}

func (s *Service) authEvent(u *iam.User, meta ReqMeta, result audit.Result, reason string) audit.Event {
	detail := map[string]any{}
	if reason != "" {
		detail["reason"] = reason
	}
	return audit.Event{
		OrganizationID: &u.OrganizationID, Action: "auth.login", Category: audit.CategoryAuth,
		ActorID: &u.ID, ActorEmail: u.Email.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: result, Detail: detail,
	}
}
