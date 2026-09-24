package iam

import (
	"context"
	"fmt"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// CreateUser creates a local user in the actor's organization and assigns roles.
// The password an admin sets here is temporary: the new user is required to
// replace it at first sign-in, so the person who created the account never keeps
// working knowledge of their credential.
func (s *Service) CreateUser(ctx context.Context, actor iam.Claims, in CreateUserInput) (*Principal, error) {
	// Checked before the row is written: there is no transaction spanning Create
	// and SetRoles, so refusing afterwards would leave an orphaned user behind.
	if err := oneRole(in.RoleIDs); err != nil {
		return nil, err
	}
	if err := s.guardSuperAdminGrant(ctx, actor, in.RoleIDs, "", in.Email); err != nil {
		return nil, err
	}
	if _, err := s.guardGrantRank(ctx, actor, in.RoleIDs, nil, "", in.Email); err != nil {
		return nil, err
	}
	if err := iam.ValidatePassword(in.Password); err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	u := &iam.User{
		ID:             iam.NewID(),
		OrganizationID: actor.OrganizationID,
		Email:          iam.NewEmail(in.Email),
		Username:       in.Username,
		PasswordHash:   hash,
		AuthProvider:   iam.ProviderLocal,
		Status:         "active",
		IsSuperAdmin:   in.IsSuperAdmin && actor.IsSuperAdmin, // only a super admin can mint one
		// An admin-set password is known to someone other than its owner.
		MustChangePassword: true,
	}
	if err := s.users.Create(ctx, actor.Scope(), u); err != nil {
		return nil, err
	}
	if len(in.RoleIDs) > 0 {
		if err := s.users.SetRoles(ctx, actor.Scope(), u.ID, in.RoleIDs); err != nil {
			return nil, err
		}
	}
	created, err := s.users.GetByID(ctx, actor.Scope(), u.ID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.create",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: u.ID.String(), IP: in.Meta.IP, UserAgent: in.Meta.UserAgent,
		Result: audit.ResultSuccess})
	p := principalFromUser(created)
	return &p, nil
}

// ListUsers returns users in the actor's tenant.
func (s *Service) ListUsers(ctx context.Context, actor iam.Claims, page iam.Page) ([]Principal, error) {
	users, err := s.users.List(ctx, actor.Scope(), page)
	if err != nil {
		return nil, err
	}
	out := make([]Principal, 0, len(users))
	for i := range users {
		out = append(out, principalFromUser(&users[i]))
	}
	return out, nil
}

// GetUser loads one user in the actor's tenant.
func (s *Service) GetUser(ctx context.Context, actor iam.Claims, id iam.ID) (*Principal, error) {
	u, err := s.users.GetByID(ctx, actor.Scope(), id)
	if err != nil {
		return nil, err
	}
	p := principalFromUser(u)
	return &p, nil
}

// DeleteUser soft-deletes a user.
//
// The installation account is deliberately NOT exempt, unlike role changes and
// password resets. Removal is the one change to it that survives being wrong:
// the email uniqueness index is partial on deleted_at IS NULL, so the address
// comes free again and `guardrail seed-admin` recreates the account on the
// server. Demoting it or resetting its password leaves an account that still
// exists and still cannot let anybody back in, which is the harder hole.
//
// Removing the last super admin therefore costs a trip to the server rather
// than being unrecoverable. The console warns before it happens.
func (s *Service) DeleteUser(ctx context.Context, actor iam.Claims, id iam.ID, meta ReqMeta) error {
	if _, err := s.guardRank(ctx, actor, id, "remove their account"); err != nil {
		return err
	}
	if err := s.users.SoftDelete(ctx, actor.Scope(), id); err != nil {
		return err
	}
	// Sign the removed person out, the way a role change and a password reset
	// already do. Without this their refresh family stays open and the console's
	// active-sessions list keeps showing somebody who no longer exists — an
	// offboarded account that still reads as signed in is the wrong answer to the
	// one question that list is asked.
	//
	// It does not shorten the access token they are already holding: the auth
	// middleware verifies the JWT signature and never re-reads the user, so a
	// removed person keeps working requests until it expires (default 15 minutes,
	// GUARDRAIL_ACCESS_TOKEN_TTL). Cutting that to zero needs a revocation check
	// on every request, which is a separate change.
	_ = s.sessions.RevokeAllForUser(ctx, id, s.clock.Now())
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.delete",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: id.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess})
	return nil
}

// guardBootstrapAdmin refuses to change the ROLES or PASSWORD of the account the
// platform was installed with. Deletion is a separate question and is allowed —
// see DeleteUser for why the two differ.
//
// It applies to EVERYBODY, including other super admins and the account itself.
// That is the point: a rule that a sufficiently privileged person can switch off
// is not a protection, it is a speed bump — and the failure it prevents (an
// account that still exists but can no longer administer anything) is one that
// cannot be repaired from inside the platform.
//
// The escape hatch is deliberately outside the product: somebody with shell
// access to the server can re-run `guardrail seed-admin`. Locking yourself out
// should cost a trip to the server, not be one careless click away.
//
// A refused attempt is audited. Somebody trying to demote the installation
// account is either confused or up to something, and both are worth a record.
func (s *Service) guardBootstrapAdmin(ctx context.Context, actor iam.Claims, userID iam.ID, what string) error {
	target, err := s.users.GetByID(ctx, actor.Scope(), userID)
	if err != nil {
		// Not found is the caller's problem to report, not ours to mask.
		return err
	}
	if !target.IsBootstrapAdmin() {
		return nil
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.protected_denied",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: userID.String(), Result: audit.ResultDenied,
		Detail: map[string]any{"attempted": what, "target": target.Email.String()}})
	return fmt.Errorf("%w: %s is the account this GuardRail was installed with", iam.ErrProtectedAccount, target.Email)
}

// guardSuperAdminGrant refuses to hand out the Super Admin role unless the actor
// already holds it.
//
// Holding that role confers unrestricted access, and super admin is also what
// bypasses tenant isolation (TenantScope.IsSuperAdmin turns off row-level
// security). Without this check, any principal with user:write — an Organization
// Admin, scoped to one tenant by design — could assign the role to themselves or
// to an account they control and read every other organization's data. You can
// only grant what you already have.
//
// CreateUser applies the same rule to the is_super_admin flag; this closes the
// other door to the same privilege.
//
// Checked first, before anything is looked up, and recorded like the other
// hierarchy refusals (see guardGrantRank).
func (s *Service) guardSuperAdminGrant(ctx context.Context, actor iam.Claims, roleIDs []iam.ID, target, who string) error {
	if actor.IsSuperAdmin {
		return nil
	}
	for _, id := range roleIDs {
		if id == iam.SuperAdminRoleID {
			s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.protected_denied",
				Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
				TargetType: "user", TargetID: target, Result: audit.ResultDenied,
				Detail: map[string]any{"attempted": "give them the Super Admin role", "target": who, "reason": "role_above"}})
			return fmt.Errorf("%w: only a super admin can grant the Super Admin role", iam.ErrPermissionDenied)
		}
	}
	return nil
}

// The hierarchy.
//
// Somebody may manage another person — their role, their password, their
// account, their teams, their sign-ins — only if they outrank them. A super
// admin outranks everybody; anybody else outranks only people whose rank
// (their role's approval level) is strictly below their own. An Organization
// Admin therefore manages Operators, Auditors and Read-only users, and neither
// another Organization Admin nor a Super Admin.
//
// Before this the only rules were "nobody but a super admin grants Super
// Admin" and "nobody touches the installation account". An Organization Admin
// could demote a Super Admin — change their role to Read-only — and that was
// recorded as an ordinary, successful role change.
//
// Acting on your own account is not managing somebody else, and is left to the
// other rules (you cannot promote yourself: see guardGrantRank).
//
// One exception, on purpose: a password reset reaches people of your own rank
// as well (guardRankOrPeer). Organization Admins help each other back in when
// one is locked out; that is helping, not managing, and the reset password is
// temporary and must be replaced at next sign-in. It still never reaches
// anybody ranked above — a Super Admin's password stays out of reach.

// guardRank refuses an action on another person the actor does not outrank,
// and records the attempt. It returns the target, loaded, for the caller.
func (s *Service) guardRank(ctx context.Context, actor iam.Claims, targetID iam.ID, what string) (*iam.User, error) {
	return s.guardRankAt(ctx, actor, targetID, what, false)
}

// guardRankOrPeer is guardRank that also lets people of the actor's own rank
// through. Used for password resets only; see the note above.
func (s *Service) guardRankOrPeer(ctx context.Context, actor iam.Claims, targetID iam.ID, what string) (*iam.User, error) {
	return s.guardRankAt(ctx, actor, targetID, what, true)
}

func (s *Service) guardRankAt(ctx context.Context, actor iam.Claims, targetID iam.ID, what string, peers bool) (*iam.User, error) {
	target, err := s.users.GetByID(ctx, actor.Scope(), targetID)
	if err != nil {
		return nil, err
	}
	if targetID == actor.UserID || actor.IsSuperAdmin || actor.Level() > target.Level() ||
		(peers && actor.Level() == target.Level()) {
		return target, nil
	}
	if peers {
		s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.protected_denied",
			Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
			TargetType: "user", TargetID: targetID.String(), Result: audit.ResultDenied,
			Detail: map[string]any{"attempted": what, "target": target.Email.String(), "reason": "outranked"}})
		return nil, fmt.Errorf("%w: %s is ranked above you, so only somebody ranked at least as high can %s",
			iam.ErrPermissionDenied, target.Email, what)
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.protected_denied",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: targetID.String(), Result: audit.ResultDenied,
		Detail: map[string]any{"attempted": what, "target": target.Email.String(), "reason": "outranked"}})
	return nil, fmt.Errorf("%w: %s is ranked at or above you, so only somebody ranked higher can %s",
		iam.ErrPermissionDenied, target.Email, what)
}

// guardGrantRank refuses to hand out a role ranked at or above the actor's own:
// nobody makes somebody their equal or their superior, only somebody ranked
// above both can. A role the person already holds is not being handed out, so
// saving someone's unchanged role is not refused. It returns the roles, loaded.
//
// A refusal is recorded against the person it would have been given to — an
// attempt to hand out a role above your own is exactly what a reviewer of the
// log is looking for. target is their id, or empty for somebody not yet
// created; who names them either way.
func (s *Service) guardGrantRank(ctx context.Context, actor iam.Claims, roleIDs []iam.ID, held []iam.Role, target, who string) ([]iam.Role, error) {
	out := make([]iam.Role, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := s.roles.GetByID(ctx, actor.Scope(), id)
		if err != nil {
			return nil, err
		}
		out = append(out, *role)
		already := false
		for _, h := range held {
			already = already || h.ID == id
		}
		// Super Admin is not "rank 100": it is no limit at all, and ranks above
		// any level a custom role can be given.
		level := role.ApprovalLevel
		if role.ID == iam.SuperAdminRoleID {
			level = iam.SuperAdminLevel
		}
		if !actor.IsSuperAdmin && !already && level >= actor.Level() {
			s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.protected_denied",
				Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
				TargetType: "user", TargetID: target, Result: audit.ResultDenied,
				Detail: map[string]any{"attempted": "give them the " + role.Name + " role", "target": who, "reason": "role_above"}})
			return nil, fmt.Errorf("%w: %s is ranked at or above your own role, so only somebody ranked higher can give it",
				iam.ErrPermissionDenied, role.Name)
		}
	}
	return out, nil
}

// oneRole holds a person to a single role. A role is a whole job — Operator,
// Auditor, Organization Admin — and two of them at once made what somebody may
// do the union of two jobs nobody chose together, and their approval rank the
// higher of the two, which is easy to grant by accident with one extra tick.
// Where somebody reaches is widened with teams, not a second role.
func oneRole(roleIDs []iam.ID) error {
	if len(roleIDs) > 1 {
		return fmt.Errorf("%w: a person has one role; pick the one that fits, and use teams to widen what they reach", iam.ErrInvalidInput)
	}
	return nil
}

// AssignRoles replaces a user's role assignments.
func (s *Service) AssignRoles(ctx context.Context, actor iam.Claims, userID iam.ID, roleIDs []iam.ID, meta ReqMeta) error {
	if err := oneRole(roleIDs); err != nil {
		return err
	}
	if err := s.guardSuperAdminGrant(ctx, actor, roleIDs, userID.String(), ""); err != nil {
		return err
	}
	if err := s.guardBootstrapAdmin(ctx, actor, userID, "role change"); err != nil {
		return err
	}
	target, err := s.guardRank(ctx, actor, userID, "change their role")
	if err != nil {
		return err
	}
	granted, err := s.guardGrantRank(ctx, actor, roleIDs, target.Roles, userID.String(), target.Email.String())
	if err != nil {
		return err
	}
	if err := s.users.SetRoles(ctx, actor.Scope(), userID, roleIDs); err != nil {
		return err
	}
	// A role edited by hand is a local decision, so the account stops tracking the
	// SIEM from here on.
	//
	// Without this, an administrator's change would last exactly until its subject
	// next signed in and then be silently reverted by the sync — which is worse
	// than refusing the edit outright, because it looks like it worked. Best
	// effort: the roles are already written, and failing the whole call now would
	// report failure for a change that did happen.
	_ = s.users.SetSSOManaged(ctx, userID, false)
	// Revoking the user's active sessions forces a fresh authz snapshot.
	_ = s.sessions.RevokeAllForUser(ctx, userID, s.clock.Now())
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.assign_roles",
		Category: audit.CategoryRole, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: userID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"role_count": len(roleIDs),
			// By name, before and after: "role_count: 1" said a role changed and
			// nothing about what it was or became.
			"from": roleNames(target.Roles),
			"to":   roleNames(granted),
		}})
	return nil
}

func roleNames(rs []iam.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// ResetPasswordResult carries the temporary password back to the administrator,
// exactly once. It is never stored in the clear and never returned again.
type ResetPasswordResult struct {
	Password string
	Email    string
}

// ResetPassword sets a temporary password on somebody else's account, for when
// they have locked themselves out.
//
// Three rules, all of them load-bearing:
//
//   - You can only reset an account you could have created. A non-super-admin
//     resetting a super admin's password is account takeover with extra steps —
//     it hands them a credential for an account that outranks them — so it is
//     refused, mirroring guardSuperAdminGrant.
//   - The installation account is refused to everybody. Its recovery lives on
//     the server (`guardrail seed-admin`), which is the point: the account that
//     can restore everything must not be resettable by anyone who happens to be
//     signed in — a reset here would hand whoever performed it the keys to the
//     one account that outranks every rule in this file.
//   - The new password is TEMPORARY. must_change_password is set, so the person
//     replaces it at next sign-in and the administrator never keeps working
//     knowledge of somebody else's credential.
//
// A blank password means "generate one". A fixed, well-known default would be
// worse than no reset at all: on a privileged-access platform every account
// mid-reset would be takeable by anyone who read the documentation.
func (s *Service) ResetPassword(ctx context.Context, actor iam.Claims, userID iam.ID, chosen string, meta ReqMeta) (*ResetPasswordResult, error) {
	target, err := s.users.GetByID(ctx, actor.Scope(), userID)
	if err != nil {
		return nil, err
	}
	if target.IsBootstrapAdmin() {
		return nil, s.guardBootstrapAdmin(ctx, actor, userID, "password reset")
	}
	// Anybody ranked above is out of reach — a Super Admin's password, above
	// all. People of the actor's own rank are not: Organization Admins reset
	// each other's passwords when one is locked out (see guardRankOrPeer).
	if _, err := s.guardRankOrPeer(ctx, actor, userID, "reset their password"); err != nil {
		return nil, err
	}
	// Federated accounts have no local password to reset; saying so beats
	// silently setting one that the identity provider will never consult.
	if target.AuthProvider != iam.ProviderLocal {
		return nil, iam.ErrPasswordUnsupported
	}

	password := chosen
	if password == "" {
		password, err = iam.GenerateTemporaryPassword()
		if err != nil {
			return nil, err
		}
	}
	if err := iam.ValidatePassword(password); err != nil {
		return nil, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	if err := s.users.UpdatePasswordHash(ctx, target.ID, hash); err != nil {
		return nil, err
	}
	if err := s.users.SetMustChangePassword(ctx, target.ID, true); err != nil {
		return nil, err
	}
	// Every existing session dies. A reset is used when an account is lost or
	// suspect, and leaving the old sessions live would mean the reset changed
	// nothing for whoever is already inside.
	_ = s.sessions.RevokeAllForUser(ctx, target.ID, s.clock.Now())

	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.reset_password",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: target.ID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"target": target.Email.String(), "generated": chosen == "",
		}})
	return &ResetPasswordResult{Password: password, Email: target.Email.String()}, nil
}
