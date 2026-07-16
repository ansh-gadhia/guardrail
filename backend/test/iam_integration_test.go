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
	if _, err := svc.CreateUser(ctx, superAdmin(), appiam.CreateUserInput{
		Email: email, Username: "ituser", Password: password,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

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
