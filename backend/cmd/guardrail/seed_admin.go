package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/config"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
	"github.com/guardrail/guardrail/internal/platform/database"
)

// superAdminRoleID is the seeded "Super Admin" system role (see db/seed.sql).
var superAdminRoleID = uuid.MustParse("10000000-0000-0000-0000-000000000001")

// runSeedAdmin bootstraps a super-admin user in an existing organization. It is
// the one-time step that makes the API usable after migrations + seed. Config is
// read from the environment like the server (Twelve-Factor).
func runSeedAdmin(args []string) error {
	fs := flag.NewFlagSet("seed-admin", flag.ContinueOnError)
	email := fs.String("email", "", "super admin email (required)")
	password := fs.String("password", "", "super admin password (required, >= 12 chars)")
	orgSlug := fs.String("org", "default", "organization slug to attach the admin to")
	username := fs.String("username", "admin", "display username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || len(*password) < 12 {
		return fmt.Errorf("seed-admin: --email required and --password must be >= 12 chars")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := database.New(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()

	pg := postgres.New(db.Pool)
	orgRepo := postgres.NewOrgRepo(pg)
	userRepo := postgres.NewUserRepo(pg)
	hasher := security.NewArgon2Hasher(security.DefaultArgon2Params())

	org, err := orgRepo.GetBySlug(ctx, *orgSlug)
	if err != nil {
		return fmt.Errorf("seed-admin: organization %q not found (run migrations + seed first): %w", *orgSlug, err)
	}

	hash, err := hasher.Hash(*password)
	if err != nil {
		return err
	}
	scope := iam.TenantScope{OrganizationID: org.ID, IsSuperAdmin: true}
	user := &iam.User{
		ID:             iam.NewID(),
		OrganizationID: org.ID,
		Email:          iam.NewEmail(*email),
		Username:       *username,
		PasswordHash:   hash,
		AuthProvider:   iam.ProviderLocal,
		Status:         "active",
		IsSuperAdmin:   true,
	}
	if err := userRepo.Create(ctx, scope, user); err != nil {
		return fmt.Errorf("seed-admin: create user: %w", err)
	}
	if err := userRepo.SetRoles(ctx, scope, user.ID, []iam.ID{superAdminRoleID}); err != nil {
		return fmt.Errorf("seed-admin: assign role: %w", err)
	}

	fmt.Fprintf(os.Stdout, "created super admin %s in org %s (id=%s)\n", *email, org.Slug, user.ID)
	return nil
}
