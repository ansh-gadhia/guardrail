package iam

import (
	"context"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// CreateOrganization provisions a new tenant. Requires super-admin scope (also
// enforced by RLS on the organizations table).
func (s *Service) CreateOrganization(ctx context.Context, actor iam.Claims, in CreateOrgInput) (*iam.Organization, error) {
	if !actor.IsSuperAdmin {
		return nil, iam.ErrPermissionDenied
	}
	o := &iam.Organization{ID: iam.NewID(), Name: in.Name, Slug: in.Slug, Status: "active"}
	if err := s.orgs.Create(ctx, actor.Scope(), o); err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &o.ID, Action: "org.create",
		Category: audit.CategoryOrg, ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "organization", TargetID: o.ID.String(), IP: in.Meta.IP, UserAgent: in.Meta.UserAgent,
		Result: audit.ResultSuccess})
	return o, nil
}

// ListOrganizations lists tenants visible to the actor (super-admin sees all;
// a regular admin sees only their own).
func (s *Service) ListOrganizations(ctx context.Context, actor iam.Claims, page iam.Page) ([]iam.Organization, error) {
	return s.orgs.List(ctx, actor.Scope(), page)
}

// GetOrganization loads one tenant within scope.
func (s *Service) GetOrganization(ctx context.Context, actor iam.Claims, id iam.ID) (*iam.Organization, error) {
	return s.orgs.GetByID(ctx, actor.Scope(), id)
}
