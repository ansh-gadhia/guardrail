package iam

import (
	"context"

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
