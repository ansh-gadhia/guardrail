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
	if err := guardSuperAdminGrant(actor, in.RoleIDs); err != nil {
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
func (s *Service) DeleteUser(ctx context.Context, actor iam.Claims, id iam.ID, meta ReqMeta) error {
	if err := s.users.SoftDelete(ctx, actor.Scope(), id); err != nil {
		return err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.delete",
		Category: audit.CategoryUser, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: id.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess})
	return nil
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
func guardSuperAdminGrant(actor iam.Claims, roleIDs []iam.ID) error {
	if actor.IsSuperAdmin {
		return nil
	}
	for _, id := range roleIDs {
		if id == iam.SuperAdminRoleID {
			return fmt.Errorf("%w: only a super admin can grant the Super Admin role", iam.ErrPermissionDenied)
		}
	}
	return nil
}

// AssignRoles replaces a user's role assignments.
func (s *Service) AssignRoles(ctx context.Context, actor iam.Claims, userID iam.ID, roleIDs []iam.ID, meta ReqMeta) error {
	if err := guardSuperAdminGrant(actor, roleIDs); err != nil {
		return err
	}
	if err := s.users.SetRoles(ctx, actor.Scope(), userID, roleIDs); err != nil {
		return err
	}
	// Revoking the user's active sessions forces a fresh authz snapshot.
	_ = s.sessions.RevokeAllForUser(ctx, userID, s.clock.Now())
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "user.assign_roles",
		Category: audit.CategoryRole, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "user", TargetID: userID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{"role_count": len(roleIDs)}})
	return nil
}
