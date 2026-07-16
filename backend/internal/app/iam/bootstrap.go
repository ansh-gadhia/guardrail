package iam

import (
	"context"
	"fmt"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// SuperAdminRoleID is the seeded "Super Admin" system role (see db/seed.sql).
//
// Defined in the domain, because holding this role is what makes a principal a
// super admin (iam.User.HasSuperAdmin). Aliased here for the existing callers.
var SuperAdminRoleID = iam.SuperAdminRoleID

// BootstrapAdminInput describes the primary super-admin seeded from the
// environment on first boot. All fields come from GUARDRAIL_ADMIN_* config, so an
// operator can set (and change) the primary credential in .env before first start.
type BootstrapAdminInput struct {
	Email    string
	Password string
	Username string
	OrgSlug  string
}

// EnsureBootstrapAdmin idempotently creates the primary super admin from config.
// It is a no-op when no email/password is configured (self-managed deployments
// use `seed-admin`), or when a user with that email already exists — so it is
// safe to run on every boot. It fails closed on a weak password.
//
// Returns true only when it actually created the account.
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, in BootstrapAdminInput) (bool, error) {
	if in.Email == "" && in.Password == "" {
		return false, nil // bootstrap not configured
	}
	if in.Email == "" || in.Password == "" {
		return false, fmt.Errorf("bootstrap admin: both GUARDRAIL_ADMIN_EMAIL and GUARDRAIL_ADMIN_PASSWORD must be set")
	}
	orgSlug := in.OrgSlug
	if orgSlug == "" {
		orgSlug = "default"
	}
	org, err := s.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return false, fmt.Errorf("bootstrap admin: organization %q not found (run migrations + seed first): %w", orgSlug, err)
	}
	email := iam.NewEmail(in.Email)

	// Idempotency: skip if this admin already exists in the org. This is checked
	// before the password policy so that tightening the policy never turns a
	// restart of an existing deployment into a boot failure — the password in the
	// environment is not used when no account is created.
	if existing, err := s.users.GetByEmailInOrg(ctx, org.ID, email); err == nil && existing != nil {
		return false, nil
	}

	// This account holds the keys to the whole estate, so it is held to the same
	// policy as every other local password.
	if err := iam.ValidatePassword(in.Password); err != nil {
		return false, fmt.Errorf("bootstrap admin: GUARDRAIL_ADMIN_PASSWORD is too weak "+
			"(at least %d characters, mixing cases/digits/symbols, and not built on a common word): %w",
			iam.MinPasswordLen, err)
	}

	username := in.Username
	if username == "" {
		username = "admin"
	}
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return false, err
	}
	scope := iam.TenantScope{OrganizationID: org.ID, IsSuperAdmin: true}
	user := &iam.User{
		ID:             iam.NewID(),
		OrganizationID: org.ID,
		Email:          email,
		Username:       username,
		PasswordHash:   hash,
		AuthProvider:   iam.ProviderLocal,
		Status:         "active",
		IsSuperAdmin:   true,
	}
	if err := s.users.Create(ctx, scope, user); err != nil {
		return false, fmt.Errorf("bootstrap admin: create user: %w", err)
	}
	if err := s.users.SetRoles(ctx, scope, user.ID, []iam.ID{SuperAdminRoleID}); err != nil {
		return false, fmt.Errorf("bootstrap admin: assign role: %w", err)
	}
	s.record(ctx, audit.Event{
		OrganizationID: &org.ID, Action: "user.bootstrap", Category: audit.CategoryUser,
		ActorEmail: email.String(), TargetType: "user", TargetID: user.ID.String(),
		Result: audit.ResultSuccess, Detail: map[string]any{"source": "environment"},
	})
	return true, nil
}
