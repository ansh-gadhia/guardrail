//go:build integration

// IAM integration tests run against a live, migrated + seeded PostgreSQL reached
// as the least-privilege guardrail_app role (so RLS is exercised). Set
// GUARDRAIL_TEST_DSN to that role's DSN; the test is skipped otherwise.
//
//	GUARDRAIL_TEST_DSN=postgres://guardrail_app:apppass@127.0.0.1:5433/guardrail?sslmode=disable \
//	  go test -tags=integration ./test/...
package test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	appiam "github.com/guardrail/guardrail/internal/app/iam"
	"github.com/guardrail/guardrail/internal/config"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
	"github.com/guardrail/guardrail/internal/platform/database"
)

// defaultOrgID is the seeded development organization (see db/seed.sql).
var defaultOrgID = uuid.MustParse("00000000-0000-0000-0000-0000000000aa")

func newService(t *testing.T) (*appiam.Service, func()) {
	t.Helper()
	dsn := os.Getenv("GUARDRAIL_TEST_DSN")
	if dsn == "" {
		t.Skip("GUARDRAIL_TEST_DSN not set; skipping IAM integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := database.New(ctx, config.PostgresConfig{DSN: dsn, MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour})
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	pg := postgres.New(db.Pool)
	hasher := security.NewArgon2Hasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	svc := appiam.NewService(appiam.Deps{
		Users:    postgres.NewUserRepo(pg),
		Orgs:     postgres.NewOrgRepo(pg),
		Roles:    postgres.NewRoleRepo(pg),
		Sessions: postgres.NewAuthSessionRepo(pg),
		Hasher:   hasher,
		Tokens:   security.NewJWTIssuer("integration-test-signing-key-32bytes!", "guardrail", 15*time.Minute),
		Refresh:  security.NewRefreshGenerator(),
		Audit:    postgres.NewAuditRepo(pg),
		Config:   appiam.DefaultConfig(),
	})
	return svc, db.Close
}

func superAdmin() iam.Claims {
	return iam.Claims{UserID: uuid.New(), OrganizationID: defaultOrgID, Email: "root@system", IsSuperAdmin: true}
}

func TestIntegration_UserLifecycleAndAuth(t *testing.T) {
	svc, closeDB := newService(t)
	defer closeDB()
	ctx := context.Background()

	email := "it-" + uuid.NewString()[:8] + "@example.com"
	password := "IntegrationPass123!"

	// Create a user via the real Postgres repositories.
	created, err := svc.CreateUser(ctx, superAdmin(), appiam.CreateUserInput{
		Email: email, Username: "ituser", Password: password,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	trackUser(t, created.UserID)

	// Log in (exercises GetByEmailGlobal, Argon2 verify, token + session persist).
	pair, err := svc.Login(ctx, appiam.LoginInput{Email: email, Password: password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected access + refresh tokens")
	}

	// Wrong password is rejected.
	if _, err := svc.Login(ctx, appiam.LoginInput{Email: email, Password: "wrong-password-1"}); err == nil {
		t.Fatal("expected wrong password to fail")
	}

	// Refresh rotates; reusing the old token is detected.
	rotated, err := svc.Refresh(ctx, pair.RefreshToken, appiam.ReqMeta{})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == pair.RefreshToken {
		t.Fatal("refresh did not rotate")
	}
	if _, err := svc.Refresh(ctx, pair.RefreshToken, appiam.ReqMeta{}); err == nil {
		t.Fatal("expected reuse of old refresh token to fail")
	}
}

// The account GuardRail was installed with cannot be demoted or removed, by
// anybody — including other super admins and itself.
//
// It is the recovery path: every other privileged account can be recreated by
// it, and nothing inside the product can recreate it. A rule that a sufficiently
// privileged person can switch off is not a protection, so this is checked for
// the strongest caller there is.
func TestIntegration_BootstrapAdminCannotBeDemotedButCanBeRemoved(t *testing.T) {
	svc, closeDB := newService(t)
	defer closeDB()
	ctx := context.Background()
	actor := superAdmin()

	// The bootstrap admin is the one carrying the is_super_admin COLUMN, which is
	// what `guardrail seed-admin` sets. A console-promoted super admin holds the
	// ROLE instead and is deliberately NOT protected.
	boot, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: "boot-" + uuid.NewString()[:8] + "@example.com", Username: "boot",
		Password: "IntegrationPass123!", IsSuperAdmin: true,
	})
	if err != nil {
		t.Fatalf("create bootstrap admin: %v", err)
	}
	trackUser(t, boot.UserID)

	operatorRole := iam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000004"))
	if err := svc.AssignRoles(ctx, actor, boot.UserID, []iam.ID{operatorRole}, appiam.ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("demoting the installation account must be refused, got %v", err)
	}
	if err := svc.AssignRoles(ctx, actor, boot.UserID, nil, appiam.ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("stripping its roles must be refused, got %v", err)
	}
	if _, err := svc.ResetPassword(ctx, actor, boot.UserID, "", appiam.ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("resetting the installation account's password must be refused, got %v", err)
	}

	// It is still there, still a super admin.
	still, err := svc.GetUser(ctx, actor, boot.UserID)
	if err != nil {
		t.Fatalf("get after refused changes: %v", err)
	}
	if !still.IsSuperAdmin || !still.IsBootstrapAdmin {
		t.Fatal("the installation account lost its standing despite the change being refused")
	}

	// Removal, by contrast, is allowed: it is the one change that can be undone
	// from outside the product. The soft delete frees the email address, because
	// the uniqueness index is partial on deleted_at — which is what makes
	// `guardrail seed-admin` able to put the same account back afterwards.
	if err := svc.DeleteUser(ctx, actor, boot.UserID, appiam.ReqMeta{}); err != nil {
		t.Fatalf("removing the installation account must be allowed: %v", err)
	}
	if _, err := svc.GetUser(ctx, actor, boot.UserID); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("the removed account should be gone, got %v", err)
	}
	// The address is free again — the recovery path seed-admin depends on.
	again, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: boot.Email, Username: "boot", Password: "IntegrationPass123!", IsSuperAdmin: true,
	})
	if err != nil {
		t.Fatalf("re-seeding the same address after removal must work: %v", err)
	}
	trackUser(t, again.UserID)
	if !again.IsBootstrapAdmin {
		t.Fatal("the re-seeded account should be the installation account again")
	}
}

// Removing somebody signs them out. The console's active-session list is the
// answer to "who is in the platform right now", and an offboarded account that
// still appears there is the wrong answer to exactly that question.
//
// Note what this does NOT prove: the access token the removed person already
// holds keeps working until it expires, because the auth middleware verifies the
// JWT and never re-reads the user. This covers the refresh family only.
func TestIntegration_DeletingAUserRevokesTheirSessions(t *testing.T) {
	svc, closeDB := newService(t)
	defer closeDB()
	ctx := context.Background()
	actor := superAdmin()

	email := "gone-" + uuid.NewString()[:8] + "@example.com"
	const password = "IntegrationPass123!"
	u, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{Email: email, Username: "gone", Password: password})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	trackUser(t, u.UserID)
	if _, err := svc.Login(ctx, appiam.LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("login: %v", err)
	}

	live, err := svc.ListSessions(ctx, actor, "", false)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if countSessionsFor(live, u.UserID) == 0 {
		t.Fatal("the sign-in did not produce a session to revoke")
	}

	if err := svc.DeleteUser(ctx, actor, u.UserID, appiam.ReqMeta{}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	after, err := svc.ListSessions(ctx, actor, "", false)
	if err != nil {
		t.Fatalf("list sessions after delete: %v", err)
	}
	if n := countSessionsFor(after, u.UserID); n != 0 {
		t.Fatalf("a removed user still has %d live session(s)", n)
	}
}

func countSessionsFor(views []appiam.SessionView, userID iam.ID) int {
	n := 0
	for i := range views {
		if views[i].UserID == userID {
			n++
		}
	}
	return n
}

// An ordinary account can be escalated and downgraded freely — the protection is
// narrow on purpose, or it would be an excuse not to manage roles at all.
func TestIntegration_OrdinaryUserRolesCanBeChangedBothWays(t *testing.T) {
	svc, closeDB := newService(t)
	defer closeDB()
	ctx := context.Background()
	actor := superAdmin()

	u, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: "ord-" + uuid.NewString()[:8] + "@example.com", Username: "ord",
		Password: "IntegrationPass123!",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	trackUser(t, u.UserID)
	if u.IsBootstrapAdmin {
		t.Fatal("a user created without the super-admin flag is not the installation account")
	}

	orgAdmin := iam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000002"))
	operator := iam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000004"))

	// Escalate.
	if err := svc.AssignRoles(ctx, actor, u.UserID, []iam.ID{orgAdmin}, appiam.ReqMeta{}); err != nil {
		t.Fatalf("escalate: %v", err)
	}
	got, err := svc.GetUser(ctx, actor, u.UserID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ApprovalLevel != 50 {
		t.Fatalf("approval level after escalation = %d, want 50", got.ApprovalLevel)
	}

	// Downgrade.
	if err := svc.AssignRoles(ctx, actor, u.UserID, []iam.ID{operator}, appiam.ReqMeta{}); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	got, err = svc.GetUser(ctx, actor, u.UserID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ApprovalLevel != 10 {
		t.Fatalf("approval level after downgrade = %d, want 10", got.ApprovalLevel)
	}
}
