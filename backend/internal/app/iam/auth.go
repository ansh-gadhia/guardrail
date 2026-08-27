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
			// No target: a throttled attempt names an email, and there may be no
			// user behind it. Inventing one would be worse than leaving it blank.
			// The organization is a different matter — see attemptOrg: without it
			// this row is visible to nobody but a super admin, and a password
			// spray hitting the throttle is exactly what a tenant's own
			// administrator needs to see.
			s.record(ctx, audit.Event{OrganizationID: s.attemptOrg(ctx, email, in.Organization),
				Action: "auth.login", Category: audit.CategoryAuth,
				ActorEmail: email.String(), IP: in.Meta.IP, UserAgent: in.Meta.UserAgent,
				Result: audit.ResultDenied, Detail: map[string]any{"reason": "throttled"}})
			return nil, ErrThrottled
		}
	}

	user, attemptedOrg, err := s.resolveLoginUser(ctx, email, in.Organization)
	if errors.Is(err, iam.ErrEmailAmbiguous) {
		// Recorded before returning. This attempt used to vanish entirely: it is
		// not a failed password, so it never reached failLogin, and the early
		// return below meant no event was written at all. Every candidate account
		// was named by this attempt, so each one's organization is told about it.
		s.recordAmbiguous(ctx, email, in.Meta)
	}
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
		s.failLogin(ctx, throttleKey, nil, email, in.Meta, "unknown_user", attemptedOrg)
		return nil, iam.ErrInvalidCredentials
	}
	if user.IsLocked(now) {
		s.record(ctx, s.authEvent(user, in.Meta, audit.ResultDenied, "account_locked"))
		return nil, iam.ErrAccountLocked
	}
	if !pwOK {
		s.failLogin(ctx, throttleKey, user, email, in.Meta, "bad_password", attemptedOrg)
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
			challenge, ce := s.mfaChal.Issue(user.ID, false, now)
			if ce != nil {
				return nil, ce
			}
			s.record(ctx, s.authEvent(user, in.Meta, audit.ResultSuccess, "mfa_challenge"))
			return &TokenPair{MFARequired: true, MFAToken: challenge, Principal: principalFromUser(user)}, nil
		}
	}

	pair, err := s.issueTokens(ctx, user, in.Meta, iam.NewID(), false)
	if err != nil {
		return nil, err
	}
	s.record(ctx, s.authEvent(user, in.Meta, audit.ResultSuccess, ""))
	return pair, nil
}

// resolveLoginUser finds the account a sign-in attempt is for, and — separately
// — the organization the attempt was AIMED at, which is known in cases where the
// account is not: naming an organization on the form resolves one even when the
// email belongs to nobody. The second return is what makes a failure visible to
// the administrator responsible for it; see attemptOrg.
func (s *Service) resolveLoginUser(ctx context.Context, email iam.Email, orgSlug string) (*iam.User, *iam.ID, error) {
	if orgSlug != "" {
		org, err := s.orgs.GetBySlug(ctx, orgSlug)
		if err != nil {
			return nil, nil, iam.ErrInvalidCredentials
		}
		orgID := org.ID
		u, err := s.users.GetByEmailInOrg(ctx, org.ID, email)
		if err != nil {
			// The organization is real and was named; only the user is unknown.
			return nil, &orgID, iam.ErrInvalidCredentials
		}
		return u, &orgID, nil
	}
	candidates, err := s.users.GetByEmailGlobal(ctx, email)
	if err != nil {
		return nil, nil, err
	}
	switch len(candidates) {
	case 0:
		return nil, s.soleOrg(ctx), iam.ErrNotFound
	case 1:
		u := candidates[0]
		return &u, &u.OrganizationID, nil
	default:
		return nil, nil, iam.ErrEmailAmbiguous
	}
}

// attemptOrg works out which organization a sign-in attempt belongs to, for
// attempts that never get as far as resolving a user.
//
// Audit rows are read under row-level security: an event with a NULL
// organization is visible to super admins and to nobody else. Every failure
// against an address that does not exist therefore landed in a place the
// tenant's own Organization Admin could not look — which is precisely the
// shape of a password spray, and precisely the person who needs to see it.
func (s *Service) attemptOrg(ctx context.Context, email iam.Email, orgSlug string) *iam.ID {
	_, orgID, _ := s.resolveLoginUser(ctx, email, orgSlug)
	return orgID
}

// soleOrg returns the organization when the deployment has exactly one, and nil
// when it has several.
//
// A single-tenant install is the common case, and there "we could not tell which
// tenant this was for" is not true: there is only one, and every attempt on the
// sign-in page is an attempt on it. With more than one tenant the honest answer
// is nil — guessing would file one tenant's attack traffic in another tenant's
// ledger, and that ledger is hash-chained and cannot be corrected later.
func (s *Service) soleOrg(ctx context.Context) *iam.ID {
	orgs, err := s.orgs.List(ctx, iam.TenantScope{IsSuperAdmin: true}, iam.Page{Limit: 2})
	if err != nil || len(orgs) != 1 {
		return nil
	}
	id := orgs[0].ID
	return &id
}

// recordAmbiguous notes an attempt on an address that exists in more than one
// organization. Each one was named by the attempt, so each one is told.
func (s *Service) recordAmbiguous(ctx context.Context, email iam.Email, meta ReqMeta) {
	candidates, err := s.users.GetByEmailGlobal(ctx, email)
	if err != nil {
		return
	}
	for i := range candidates {
		orgID := candidates[i].OrganizationID
		s.record(ctx, audit.Event{
			OrganizationID: &orgID, Action: "auth.login", Category: audit.CategoryAuth,
			ActorEmail: email.String(),
			TargetType: "user", TargetID: candidates[i].ID.String(),
			IP: meta.IP, UserAgent: meta.UserAgent,
			Result: audit.ResultFailure,
			Detail: map[string]any{"reason": "email_ambiguous", "organizations": len(candidates)},
		})
	}
}

// failLogin records a failed attempt, incrementing account + throttle counters
// and locking the account when the threshold is reached.
func (s *Service) failLogin(ctx context.Context, throttleKey string, user *iam.User, email iam.Email, meta ReqMeta, reason string, orgID *iam.ID) {
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
	// No user, so no target — but an organization where one could be worked out,
	// so the tenant's administrator can see attempts on addresses that do not
	// exist rather than only on ones that do.
	s.record(ctx, audit.Event{OrganizationID: orgID, Action: "auth.login", Category: audit.CategoryAuth,
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
			ActorID: &sess.UserID, TargetType: "user", TargetID: sess.UserID.String(),
			IP: meta.IP, UserAgent: meta.UserAgent,
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
	// The rotated family keeps whatever opened it. Re-deriving this from the user
	// would be wrong in both directions: an SSO user who also signs in with a
	// password has two families with different provenance, and the same person's
	// two sessions must not silently share one.
	pair, err := s.issueTokens(ctx, user, meta, sess.FamilyID, sess.SSO)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &user.OrganizationID, Action: "auth.refresh",
		Category: audit.CategoryAuth, ActorID: &user.ID, ActorEmail: user.Email.String(),
		TargetType: "user", TargetID: user.ID.String(),
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
		ActorID: &sess.UserID, TargetType: "user", TargetID: sess.UserID.String(),
		IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultSuccess})
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
	return s.issueTokens(ctx, user, meta, iam.NewID(), false)
}

func (s *Service) pwEvent(u *iam.User, meta ReqMeta, result audit.Result, reason string) audit.Event {
	detail := map[string]any{}
	if reason != "" {
		detail["reason"] = reason
	}
	return audit.Event{
		OrganizationID: &u.OrganizationID, Action: "auth.password_change", Category: audit.CategoryAuth,
		ActorID: &u.ID, ActorEmail: u.Email.String(),
		TargetType: "user", TargetID: u.ID.String(),
		IP: meta.IP, UserAgent: meta.UserAgent,
		Result: result, Detail: detail,
	}
}

// Me returns the current principal, reloaded from storage within its scope.
func (s *Service) Me(ctx context.Context, claims iam.Claims) (*Principal, error) {
	user, err := s.users.GetByID(ctx, claims.Scope(), claims.UserID)
	if err != nil {
		return nil, err
	}
	p := s.principalOf(ctx, user)
	return &p, nil
}

// principalOf builds the public view of a user for a response the CONSOLE will
// act on, which is the reason it costs an extra read that principalFromUser does
// not: the console decides what to put in front of somebody at sign-in, and it
// cannot do that without knowing whether they already hold a second factor.
//
// One indexed lookup by primary key, on sign-in and on refresh. The admin
// listings deliberately keep the cheap path — they are answering "who exists",
// not "what should this person be shown next".
func (s *Service) principalOf(ctx context.Context, u *iam.User) Principal {
	p := principalFromUser(u)
	if s.mfa != nil {
		if m, err := s.mfa.Get(ctx, u.ID); err == nil {
			p.MFAEnabled = m.Confirmed()
		}
	}
	return p
}

// issueTokens mints an access JWT and a rotated refresh token in the given
// family, persisting the refresh session.
//
// sso marks a family opened by a SIEM exchange. It is stored on the session row
// as well as signed into the access token, because a refresh rebuilds the token
// from the user record — and a marker that lived only in the token would be lost
// at the first rotation, fifteen minutes in.
func (s *Service) issueTokens(ctx context.Context, user *iam.User, meta ReqMeta, familyID iam.ID, sso bool) (*TokenPair, error) {
	now := s.clock.Now()
	claims := claimsFromUser(user)
	claims.SSO = sso
	access, accessExp, err := s.tokens.Issue(claims, now)
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
		UserAgent: meta.UserAgent, IP: meta.IP, ExpiresAt: refreshExp, SSO: sso,
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken: access, AccessExpiresAt: accessExp,
		RefreshToken: rawRefresh, RefreshExpiresAt: refreshExp,
		Principal: s.principalOf(ctx, user),
	}, nil
}

func (s *Service) authEvent(u *iam.User, meta ReqMeta, result audit.Result, reason string) audit.Event {
	detail := map[string]any{}
	if reason != "" {
		detail["reason"] = reason
	}
	return audit.Event{
		OrganizationID: &u.OrganizationID, Action: "auth.login", Category: audit.CategoryAuth,
		ActorID: &u.ID, ActorEmail: u.Email.String(),
		// The account being signed in to. Identical to the actor on a normal
		// login, which is exactly what the console collapses to "self" — but it
		// has to be recorded to be exported, and an SSO or admin-driven flow
		// added later would make the two diverge.
		TargetType: "user", TargetID: u.ID.String(),
		IP: meta.IP, UserAgent: meta.UserAgent,
		Result: result, Detail: detail,
	}
}
