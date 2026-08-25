package iam

import (
	"context"
	"fmt"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ListRoles returns roles visible to the actor (org + system templates).
func (s *Service) ListRoles(ctx context.Context, actor iam.Claims, page iam.Page) ([]iam.Role, error) {
	return s.roles.List(ctx, actor.Scope(), page)
}

// ListPermissions returns the permission catalogue.
func (s *Service) ListPermissions(ctx context.Context) ([]iam.Permission, error) {
	return s.roles.ListPermissions(ctx)
}

// GetRoleDeviceAccess returns a role's resource-level device entitlement.
func (s *Service) GetRoleDeviceAccess(ctx context.Context, actor iam.Claims, roleID iam.ID) (*iam.RoleDeviceAccess, error) {
	return s.roles.GetDeviceAccess(ctx, actor.Scope(), roleID)
}

// SetRoleDeviceAccess replaces a role's device scope and grants. A scope of
// "scoped" with no types and no groups is a valid (deny-all) configuration.
func (s *Service) SetRoleDeviceAccess(ctx context.Context, actor iam.Claims, roleID iam.ID, in iam.RoleDeviceAccess, meta ReqMeta) error {
	if in.Scope != iam.DeviceScopeAll && in.Scope != iam.DeviceScopeScoped {
		return iam.ErrInvalidInput
	}
	// When unrestricted, the type/group grants are meaningless — clear them so the
	// stored state is unambiguous.
	if in.Scope == iam.DeviceScopeAll {
		in.DeviceTypes, in.GroupIDs = nil, nil
	}
	if err := s.systemRoleGuard(ctx, actor, roleID); err != nil {
		return err
	}
	if err := s.roles.SetDeviceAccess(ctx, actor.Scope(), roleID, in); err != nil {
		return err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "role.set_device_access",
		Category: audit.CategoryRole, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "role", TargetID: roleID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{
			"scope": string(in.Scope), "device_types": len(in.DeviceTypes), "groups": len(in.GroupIDs),
		}})
	return nil
}

// SetRoleApprovalLevel changes a role's rank in the approval hierarchy.
//
// Ranks are compared strictly, so this is the one dial that decides who can sign
// off whose access. Changing it is audited for that reason.
func (s *Service) SetRoleApprovalLevel(ctx context.Context, actor iam.Claims, roleID iam.ID, level int, meta ReqMeta) error {
	if level < 0 || level > 999 {
		return fmt.Errorf("%w: approval level must be between 0 and 999", iam.ErrInvalidInput)
	}
	if err := s.systemRoleGuard(ctx, actor, roleID); err != nil {
		return err
	}
	if err := s.roles.SetApprovalLevel(ctx, actor.Scope(), roleID, level); err != nil {
		return err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "role.approval_level",
		Category: audit.CategoryRole, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "role", TargetID: roleID.String(), IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: map[string]any{"level": level}})
	return nil
}

// ApprovalCoverage reports whether anybody could approve a request made at each
// rank currently held by an active user.
//
// It exists so the console can refuse to gate a device nobody can be approved
// onto. The alternative is a person waiting out a thirty-minute window on a
// decision that was never going to arrive, and finding out at exactly the wrong
// moment.
func (s *Service) ApprovalCoverage(ctx context.Context, actor iam.Claims) (map[int]int, error) {
	levels, err := s.roles.LevelsInUse(ctx, actor.Scope())
	if err != nil {
		return nil, err
	}
	out := make(map[int]int, len(levels))
	for _, l := range levels {
		if _, seen := out[l]; seen {
			continue
		}
		n, cerr := s.roles.ApproverCountAbove(ctx, actor.Scope(), l)
		if cerr != nil {
			return nil, cerr
		}
		out[l] = n
	}
	return out, nil
}

// systemRoleGuard refuses an edit to a role this tenant does not own.
//
// System roles — Super Admin, Organization Admin, Operator, Auditor, Read-only —
// carry a NULL organization_id and are shared by every tenant on the
// deployment. One organization editing "Operator" would change it for all of
// them, so the RLS policy on roles admits them for READING and refuses to write
// them back: USING allows organization_id IS NULL, WITH CHECK does not.
//
// That is the correct rule, and it was being enforced in the worst possible
// place. The service issued the UPDATE anyway, Postgres rejected the resulting
// row, and the console showed "new row violates row-level security policy for
// table roles" as a 500 — an internal error for something that is simply not
// allowed. An Organization Admin editing any seeded role hit it every time.
//
// Refused here instead, with a reason and a way forward.
func (s *Service) systemRoleGuard(ctx context.Context, actor iam.Claims, roleID iam.ID) error {
	if actor.IsSuperAdmin {
		return nil
	}
	role, err := s.roles.GetByID(ctx, actor.Scope(), roleID)
	if err != nil {
		return err
	}
	if role.OrganizationID == nil {
		return fmt.Errorf("%w: %q is a built-in role shared by every organization on this deployment, "+
			"so it cannot be changed for one of them. Create a role of your own and edit that instead",
			iam.ErrPermissionDenied, role.Name)
	}
	return nil
}
