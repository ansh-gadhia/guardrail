package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// SSOConfig is the policy around SIEM-vouched sign-in. Every field defaults to
// the behaviour a deployment that has never heard of the SIEM already has.
type SSOConfig struct {
	// JITProvision creates the account on first sign-in instead of refusing.
	//
	// The alternative is the SIEM holding standing GuardRail administrator
	// credentials purely to pre-register people — a permanent privileged
	// credential on a privileged-access broker, held by a machine, for the sole
	// purpose of writing rows. Provisioning from the token removes it entirely.
	JITProvision bool
	// SyncOnLogin re-applies the mapped role to SIEM-owned accounts each sign-in,
	// so a promotion or a demotion in the SIEM lands without anybody touching
	// GuardRail.
	SyncOnLogin bool
	// TrustAMR accepts the SIEM's word that it verified a second factor, and so
	// skips GuardRail's own. Off by default: "the SIEM says they did MFA" and
	// "this person just proved possession of a factor GuardRail knows about" are
	// different claims, and only the second survives the SIEM being wrong about
	// it. A forged exchange token asserts amr just as easily as it asserts a role.
	TrustAMR bool
	// MaxRole is the ceiling on any SIEM-derived role, named as a GuardRail role.
	// Empty means no ceiling beyond the hard bar on Super Admin, which is not
	// configurable and applies regardless.
	//
	// It exists because once the token can choose the role, a FORGED token can
	// choose the role. Set it below Organization Admin and no SIEM sign-in
	// reaches administration no matter what any claim says.
	MaxRole string
	// NonceFloor and NonceCeiling bound how long a spent nonce is remembered. The
	// real value comes from the token; see iam.SSOAssertion.ReplayRetention.
	NonceFloor   time.Duration
	NonceCeiling time.Duration
}

// DefaultSSOConfig returns the shipped policy.
func DefaultSSOConfig() SSOConfig {
	return SSOConfig{
		JITProvision: true,
		SyncOnLogin:  true,
		TrustAMR:     false,
		NonceFloor:   5 * time.Minute,
		NonceCeiling: time.Hour,
	}
}

// SIEMSSOEnabled reports whether an exchange could succeed on this deployment.
//
// All four collaborators are required. In particular the provisioning
// organization is: without it there is no answer to "which tenant is this person
// in", and the one place that must never answer it is the token.
func (s *Service) SIEMSSOEnabled() bool {
	return s.ssoVerify != nil && s.ssoVerify.Configured() &&
		s.replay != nil && s.ssoRoles != nil && s.fedOrgID != (iam.ID{})
}

// LoginWithSIEM trades a SIEM exchange token for a GuardRail session.
//
// The order below is the contract, and each step is where it is for a reason
// spelled out at the step. Read as a whole: nothing is trusted before the
// signature, the token is spent before it can do any work, the account is
// resolved by a key that survives a rename, privilege is decided by GuardRail's
// own table rather than by the claim, and the account's own second factor is
// still asked for.
func (s *Service) LoginWithSIEM(ctx context.Context, rawToken string, meta ReqMeta) (*TokenPair, error) {
	if !s.SIEMSSOEnabled() {
		return nil, iam.ErrSSONotConfigured
	}

	// A public, unauthenticated endpoint gets the same brute-force treatment as
	// the sign-in form. Keyed on source address alone: unlike a password login
	// there is no email to key on until the token has been verified, and keying
	// on something the token asserts would let an attacker pick their own bucket.
	throttleKey := "sso:" + meta.IP
	if s.throttle != nil {
		if ok, _, err := s.throttle.Allow(ctx, throttleKey); err == nil && !ok {
			s.recordSSO(ctx, nil, meta, audit.ResultDenied, "throttled", nil)
			return nil, ErrThrottled
		}
	}

	// 1. Verify. Signature, algorithm routing, key resolution, audience, issuer,
	// purpose, expiry and claimed lifetime all happen in here, and nothing is
	// read out of the token before its signature has vouched for it.
	assertion, err := s.ssoVerify.VerifySSOToken(ctx, rawToken)
	if err != nil {
		// An unavailable verifier is GuardRail's fault and must not count against
		// the caller's throttle budget, or a JWKS outage would lock out every
		// address that tried during it — long after the outage ended.
		if !errors.Is(err, iam.ErrSSOUnavailable) && s.throttle != nil {
			_ = s.throttle.Fail(ctx, throttleKey)
		}
		s.recordSSO(ctx, nil, meta, audit.ResultFailure, "token_rejected",
			map[string]any{"error": err.Error()})
		return nil, err
	}

	// 2. Spend the nonce, before anything is created, changed or issued.
	//
	// Ordered here deliberately: a replayed token that provisioned an account and
	// synced a role before being refused would have done most of its damage
	// already, and the audit trail would show the work without the refusal.
	if err := s.spendSSONonce(ctx, assertion, meta); err != nil {
		return nil, err
	}

	// 3. Resolve the person — by subject, then by email — and reconcile the two.
	orgID := s.fedOrgID
	user, err := s.resolveSSOUser(ctx, orgID, assertion, meta)
	if err != nil {
		return nil, err
	}

	// 4. Provision, if this is somebody's first sign-in.
	if user == nil {
		if !s.ssoCfg.JITProvision {
			s.recordSSO(ctx, nil, meta, audit.ResultDenied, "unknown_user", nil)
			return nil, fmt.Errorf("%w: this person has no GuardRail account and "+
				"just-in-time provisioning is switched off here", iam.ErrSSOToken)
		}
		if assertion.Email == "" {
			// A subject alone finds an account; it cannot invent one. There is
			// nothing to put in the email column, which is the login identifier.
			s.recordSSO(ctx, nil, meta, audit.ResultDenied, "no_email", nil)
			return nil, fmt.Errorf("%w: the token carries no email claim, so no account "+
				"can be created for it", iam.ErrSSOToken)
		}
		if user, err = s.provisionSSOUser(ctx, orgID, assertion, meta); err != nil {
			return nil, err
		}
	} else if s.ssoCfg.SyncOnLogin {
		// 5. Sync. Only for accounts the SIEM owns — see syncSSORoles.
		s.syncSSORoles(ctx, user, assertion, meta)
	}

	// 6. Refuse a disabled or locked account — AFTER provisioning and sync, so
	// that re-enabling somebody in the SIEM lands before the gate rather than one
	// sign-in after it.
	now := s.clock.Now()
	if user.IsLocked(now) {
		s.recordSSO(ctx, user, meta, audit.ResultDenied, "account_locked", nil)
		return nil, iam.ErrAccountLocked
	}
	if user.Status != "active" {
		s.recordSSO(ctx, user, meta, audit.ResultDenied, "inactive", nil)
		return nil, iam.ErrAccountInactive
	}

	if s.throttle != nil {
		_ = s.throttle.Reset(ctx, throttleKey)
	}
	_ = s.users.RecordLoginSuccess(ctx, user.ID, now)

	// 7. GuardRail's own second factor, if this person has one.
	//
	// The SIEM authenticated them; it did not authenticate them TO GUARDRAIL's
	// satisfaction if they have chosen to hold a factor here. Skipping it because
	// a claim in the token says MFA happened would mean a forged token bypasses
	// the one control that a forged token cannot itself satisfy — which is the
	// whole reason somebody enrolled it.
	if s.mfa != nil && !(s.ssoCfg.TrustAMR && assertion.AssertsMFA()) {
		if m, e := s.mfa.Get(ctx, user.ID); e == nil && m.Confirmed() {
			challenge, ce := s.mfaChal.Issue(user.ID, true, now)
			if ce != nil {
				return nil, ce
			}
			s.recordSSO(ctx, user, meta, audit.ResultSuccess, "mfa_challenge", nil)
			return &TokenPair{MFARequired: true, MFAToken: challenge, Principal: principalFromUser(user)}, nil
		}
	}

	pair, err := s.issueTokens(ctx, user, meta, iam.NewID(), true)
	if err != nil {
		return nil, err
	}
	s.recordSSO(ctx, user, meta, audit.ResultSuccess, "", map[string]any{
		"asserted": Provenance(assertion.Role, assertion.Access),
		"roles":    user.RoleNames(),
	})
	return pair, nil
}

// spendSSONonce makes the token single-use.
//
// Fails CLOSED on a store error, which is a deliberate departure from how the
// login throttle a few files over treats the same outage. The throttle fails
// open because account lockout still backstops it; nothing backstops a replayed
// exchange token. It is a bearer credential whose single-use property is
// enforced in exactly one place, and the session it opens on this product can
// connect to a device. Redis is already a hard dependency of this process — it
// is in the readiness probe — so a deployment that cannot reach it is not
// serving logins anyway, and failing open here would buy an availability that
// does not exist.
func (s *Service) spendSSONonce(ctx context.Context, a *iam.SSOAssertion, meta ReqMeta) error {
	ttl := a.ReplayRetention(s.clock.Now(), s.ssoCfg.NonceFloor, s.ssoCfg.NonceCeiling)
	fresh, err := s.replay.Consume(ctx, a.Nonce, ttl)
	if err != nil {
		s.recordSSO(ctx, nil, meta, audit.ResultFailure, "replay_store_unavailable",
			map[string]any{"error": err.Error()})
		return fmt.Errorf("%w: the replay store could not be reached", iam.ErrSSOUnavailable)
	}
	if !fresh {
		s.recordSSO(ctx, nil, meta, audit.ResultDenied, "replay", nil)
		return fmt.Errorf("%w: this exchange token has already been used", iam.ErrSSOToken)
	}
	return nil
}

// resolveSSOUser finds the account this assertion belongs to, or nil when there
// is none yet. It also reconciles what the token says with what is stored.
func (s *Service) resolveSSOUser(ctx context.Context, orgID iam.ID, a *iam.SSOAssertion, meta ReqMeta) (*iam.User, error) {
	// By subject first: the key that survives a rename.
	if a.Subject != "" {
		u, err := s.users.GetBySIEMSubject(ctx, orgID, a.Subject)
		switch {
		case err == nil:
			s.reconcileEmail(ctx, u, a, meta)
			return u, nil
		case !errors.Is(err, iam.ErrNotFound):
			return nil, err
		}
	}

	// Then by email, so accounts that predate SIEM sign-in — locally created
	// users, an LDAP account, somebody an administrator set up last year — are
	// found rather than duplicated.
	if a.Email == "" {
		return nil, nil
	}
	u, err := s.users.GetByEmailInOrg(ctx, orgID, iam.NewEmail(a.Email))
	if errors.Is(err, iam.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.backfillSubject(ctx, u, a, meta)
	return u, nil
}

// backfillSubject adopts the token's subject onto an account that was matched by
// email and has none.
//
// This is what makes the migration to subject-keying free: no window, no
// coordinated cutover, no script. Every account adopts its identity on its
// owner's next sign-in and is rename-proof from then on. Accounts whose owners
// never use the SIEM simply never adopt one, which is correct.
func (s *Service) backfillSubject(ctx context.Context, u *iam.User, a *iam.SSOAssertion, meta ReqMeta) {
	if a.Subject == "" || u.SSO.Subject == a.Subject {
		return
	}
	if u.SSO.Subject != "" {
		// This account already belongs to a different SIEM identity. Two people
		// sharing an address is not something to paper over by moving the link.
		s.recordSSO(ctx, u, meta, audit.ResultDenied, "subject_conflict", map[string]any{
			"stored": u.SSO.Subject, "asserted": a.Subject,
		})
		return
	}
	ident := u.SSO
	ident.Subject = a.Subject
	if err := s.users.SetSSOIdentity(ctx, u.ID, ident); err != nil {
		// Never fatal. The sign-in is valid either way; the account simply stays
		// email-keyed until next time.
		s.recordSSO(ctx, u, meta, audit.ResultFailure, "subject_backfill_failed",
			map[string]any{"error": err.Error()})
		return
	}
	u.SSO = ident
	s.record(ctx, audit.Event{OrganizationID: &u.OrganizationID, Action: "auth.sso.reconcile",
		Category: audit.CategoryAuth, ActorID: &u.ID, ActorEmail: u.Email.String(),
		TargetType: "user", TargetID: u.ID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{"backfilled_subject": a.Subject}})
}

// reconcileEmail updates the stored address when the SIEM reports a new one for
// a subject GuardRail already knows.
//
// Trusted only because the match came from the subject. An account found BY
// email tells you nothing new about its own email, so the backfill path above
// deliberately does not do this.
func (s *Service) reconcileEmail(ctx context.Context, u *iam.User, a *iam.SSOAssertion, meta ReqMeta) {
	next := iam.NewEmail(a.Email)
	if next == "" || next == u.Email {
		return
	}
	if err := s.users.UpdateEmail(ctx, u.ID, next); err != nil {
		// A collision means somebody else in this tenant already holds the
		// address. Logged and skipped: failing an entire sign-in over a display
		// attribute is the wrong trade, and the person can still work.
		s.recordSSO(ctx, u, meta, audit.ResultFailure, "email_rename_skipped", map[string]any{
			"from": u.Email.String(), "to": next.String(), "error": err.Error(),
		})
		return
	}
	s.record(ctx, audit.Event{OrganizationID: &u.OrganizationID, Action: "auth.sso.reconcile",
		Category: audit.CategoryAuth, ActorID: &u.ID, ActorEmail: next.String(),
		TargetType: "user", TargetID: u.ID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"renamed_from": u.Email.String(), "renamed_to": next.String()}})
	u.Email = next
}

// provisionSSOUser creates the account on first sign-in.
func (s *Service) provisionSSOUser(ctx context.Context, orgID iam.ID, a *iam.SSOAssertion, meta ReqMeta) (*iam.User, error) {
	roleID, roleName, recognised := s.resolveSSORole(ctx, orgID, a)

	u := &iam.User{
		ID:             iam.NewID(),
		OrganizationID: orgID,
		Email:          iam.NewEmail(a.Email),
		Username:       a.Username,
		AuthProvider:   iam.ProviderSIEM,
		Status:         "active",
		// No password hash and no forced change. This account cannot be reached
		// through the password login path at all — Login refuses any provider but
		// local — so there is deliberately nothing to set, not even something
		// random: a credential that exists is a credential that can be attacked.
		IsSuperAdmin: false,
		SSO: iam.SSOIdentity{
			Subject:    a.Subject,
			Managed:    true,
			SourceRole: Provenance(a.Role, a.Access),
		},
	}
	err := s.users.Create(ctx, iam.TenantScope{OrganizationID: orgID, IsSuperAdmin: true}, u)
	if errors.Is(err, iam.ErrConflict) {
		// Two first sign-ins for the same person, racing. Not an error to report:
		// the other one won, so look the account up and carry on.
		if existing, e := s.resolveSSOUser(ctx, orgID, a, meta); e == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if roleID != (iam.ID{}) {
		if e := s.users.SetRoles(ctx, iam.TenantScope{OrganizationID: orgID, IsSuperAdmin: true},
			u.ID, []iam.ID{roleID}); e != nil {
			return nil, e
		}
	}

	created, err := s.users.GetByID(ctx, iam.TenantScope{OrganizationID: orgID, IsSuperAdmin: true}, u.ID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &orgID, Action: "auth.sso.provision",
		Category: audit.CategoryUser, ActorID: &created.ID, ActorEmail: created.Email.String(),
		TargetType: "user", TargetID: created.ID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"asserted": Provenance(a.Role, a.Access), "role": roleName, "role_recognised": recognised,
			"subject": a.Subject,
		}})
	return created, nil
}

// syncSSORoles re-applies the mapped role to an account the SIEM owns.
//
// Two guards, both load-bearing:
//
//   - Only SIEM-owned accounts. sso_managed is cleared the moment a GuardRail
//     administrator edits the roles by hand (see AssignRoles), so a deliberate
//     local decision survives instead of lasting exactly until its subject next
//     signs in.
//   - Only when the ROLE claim was recognised. A SIEM that stops sending it — a
//     rename, a schema change, a bug on their side — would otherwise silently
//     demote every analyst to the default on their next sign-in, and the first
//     symptom would be a room full of people who cannot reach anything.
//
// Failures are logged, never fatal. A sync that cannot be applied is a stale
// role, not a reason to refuse somebody who has authenticated correctly.
func (s *Service) syncSSORoles(ctx context.Context, u *iam.User, a *iam.SSOAssertion, meta ReqMeta) {
	if !u.SSO.Managed {
		return
	}
	roleID, roleName, recognised := s.resolveSSORole(ctx, u.OrganizationID, a)
	if !recognised || roleID == (iam.ID{}) {
		return
	}
	before := u.RoleNames()
	// Only write when something actually differs, so a sign-in is not an
	// unconditional write to the role graph and the audit trail records real
	// changes rather than one row per login.
	if len(before) == 1 && strings.EqualFold(before[0], roleName) &&
		u.SSO.SourceRole == Provenance(a.Role, a.Access) {
		return
	}
	scope := iam.TenantScope{OrganizationID: u.OrganizationID, IsSuperAdmin: true}
	if err := s.users.SetRoles(ctx, scope, u.ID, []iam.ID{roleID}); err != nil {
		s.recordSSO(ctx, u, meta, audit.ResultFailure, "role_sync_failed",
			map[string]any{"error": err.Error()})
		return
	}
	ident := u.SSO
	ident.SourceRole = Provenance(a.Role, a.Access)
	if err := s.users.SetSSOIdentity(ctx, u.ID, ident); err == nil {
		u.SSO = ident
	}
	if refreshed, err := s.users.GetByID(ctx, scope, u.ID); err == nil {
		*u = *refreshed
	}
	s.record(ctx, audit.Event{OrganizationID: &u.OrganizationID, Action: "auth.sso.sync",
		Category: audit.CategoryRole, ActorID: &u.ID, ActorEmail: u.Email.String(),
		TargetType: "user", TargetID: u.ID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"asserted": Provenance(a.Role, a.Access), "from": before, "to": roleName,
		}})
}

// resolveSSORole turns an assertion into a GuardRail role id, applying the hard
// bar and then the configured ceiling.
//
// Returns the zero id when nothing could be resolved, which leaves the account's
// roles alone rather than clearing them.
func (s *Service) resolveSSORole(ctx context.Context, orgID iam.ID, a *iam.SSOAssertion) (iam.ID, string, bool) {
	wanted, recognised := s.ssoRoles.Resolve(a.Role, a.Access)

	scope := iam.TenantScope{OrganizationID: orgID, IsSuperAdmin: true}
	roles, err := s.roles.List(ctx, scope, iam.Page{Limit: 200})
	if err != nil {
		return iam.ID{}, "", false
	}

	role := findRoleByName(roles, wanted)
	if role == nil {
		// The map names a role this deployment does not have. A sign-in must not
		// fail over that, and it must never guess upward, so it falls to the
		// default — which is itself only as privileged as Read-only unless an
		// administrator changed it.
		role = findRoleByName(roles, s.ssoRoles.Default())
		recognised = false
	}
	if role == nil {
		return iam.ID{}, "", false
	}

	// The hard bar. Super Admin is not "a bigger administrator" — it is the role
	// that turns row-level security OFF, so it reads and writes every tenant on
	// the deployment. Letting a claim in a token select it would mean anybody who
	// could forge one owns the whole installation, and anybody who compromised
	// the SIEM owns it too. There is no configuration that lifts this, which is
	// the point: a rule a sufficiently privileged setting can switch off is not a
	// rule.
	if role.ID == iam.SuperAdminRoleID {
		role = findRoleByName(roles, s.ssoRoles.Default())
		recognised = false
		if role == nil || role.ID == iam.SuperAdminRoleID {
			return iam.ID{}, "", false
		}
	}

	// The configurable ceiling, on top. Once the token can pick a role, a forged
	// token can pick a role; this is how a deployment says how much that is
	// allowed to be worth.
	if ceiling := strings.TrimSpace(s.ssoCfg.MaxRole); ceiling != "" {
		if limit := findRoleByName(roles, ceiling); limit != nil && role.ApprovalLevel > limit.ApprovalLevel {
			role = limit
		}
	}
	return role.ID, role.Name, recognised
}

// findRoleByName matches case-insensitively, so an override or a ceiling may
// spell a role however an operator naturally would.
func findRoleByName(roles []iam.Role, name string) *iam.Role {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	for i := range roles {
		if strings.EqualFold(strings.TrimSpace(roles[i].Name), strings.TrimSpace(name)) {
			return &roles[i]
		}
	}
	return nil
}

// recordSSO writes one exchange-endpoint audit row.
//
// user may be nil: most of the failures here happen before any account has been
// resolved, and a row that names nobody is still the row that shows somebody
// hammering the exchange endpoint with forged tokens.
func (s *Service) recordSSO(ctx context.Context, u *iam.User, meta ReqMeta, result audit.Result, reason string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	if reason != "" {
		detail["reason"] = reason
	}
	e := audit.Event{
		Action: "auth.sso", Category: audit.CategoryAuth,
		IP: meta.IP, UserAgent: meta.UserAgent, Result: result, Detail: detail,
	}
	if u != nil {
		e.OrganizationID = &u.OrganizationID
		e.ActorID = &u.ID
		e.ActorEmail = u.Email.String()
		e.TargetType, e.TargetID = "user", u.ID.String()
	} else if s.fedOrgID != (iam.ID{}) {
		// No account, but the tenant is known from configuration. Without this the
		// row carries a NULL organization and is visible to super admins only —
		// and a stream of rejected exchange tokens is exactly what the tenant's
		// own administrator needs to see.
		orgID := s.fedOrgID
		e.OrganizationID = &orgID
	}
	s.record(ctx, e)
}
