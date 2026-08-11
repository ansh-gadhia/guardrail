//go:build integration

// API token integration tests, run against a live migrated + seeded PostgreSQL
// reached as the least-privilege guardrail_app role so RLS is exercised.
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

// newTokenService builds a service wired with the API token repository, which
// newService (used by the IAM tests) deliberately leaves out.
func newTokenService(t *testing.T) (*appiam.Service, func()) {
	t.Helper()
	dsn := os.Getenv("GUARDRAIL_TEST_DSN")
	if dsn == "" {
		t.Skip("GUARDRAIL_TEST_DSN not set; skipping API token integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := database.New(ctx, config.PostgresConfig{DSN: dsn, MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour})
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	pg := postgres.New(db.Pool)
	svc := appiam.NewService(appiam.Deps{
		Users:     postgres.NewUserRepo(pg),
		Orgs:      postgres.NewOrgRepo(pg),
		Roles:     postgres.NewRoleRepo(pg),
		Sessions:  postgres.NewAuthSessionRepo(pg),
		APITokens: postgres.NewAPITokenRepo(pg),
		Hasher:    security.NewArgon2Hasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}),
		Tokens:    security.NewJWTIssuer("integration-test-signing-key-32bytes!", "guardrail", 15*time.Minute),
		Refresh:   security.NewRefreshGenerator(),
		Audit:     postgres.NewAuditRepo(pg),
		Config:    appiam.DefaultConfig(),
	})
	return svc, db.Close
}

// tokenIssuer returns claims whose UserID belongs to a user that actually
// exists.
//
// api_tokens.created_by is a foreign key to users — issuing a machine credential
// is an act somebody is accountable for — so the synthetic superAdmin() actor
// the other integration tests use cannot mint one. Its random UUID fails the
// constraint, which mapWriteErr reports as "not found".
func tokenIssuer(ctx context.Context, t *testing.T, svc *appiam.Service) iam.Claims {
	t.Helper()
	email := "tok-" + uuid.NewString()[:8] + "@example.com"
	u, err := svc.CreateUser(ctx, superAdmin(), appiam.CreateUserInput{
		Email: email, Username: "tokissuer", Password: "IntegrationPass123!",
	})
	if err != nil {
		t.Fatalf("create issuing user: %v", err)
	}
	return iam.Claims{UserID: u.UserID, OrganizationID: defaultOrgID, Email: email, IsSuperAdmin: true}
}

// A freshly created token must come back with the timestamp the DATABASE
// assigned, not the zero value.
//
// created_at is filled by a column DEFAULT, so an INSERT that does not read it
// back leaves the struct at Go's zero time. That serialises as
// "0001-01-01T00:00:00Z" and renders in the console as the year 1 — on the
// create response, the one response somebody is looking at closely.
func TestCreateAPITokenReturnsDatabaseTimestamp(t *testing.T) {
	svc, closeDB := newTokenService(t)
	defer closeDB()
	ctx := context.Background()
	actor := tokenIssuer(ctx, t, svc)

	before := time.Now().Add(-time.Minute)
	res, err := svc.CreateAPIToken(ctx, actor, "integration-created-at", []string{"device:read"}, nil, appiam.ReqMeta{})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	defer func() { _ = svc.RevokeAPIToken(ctx, actor, res.Token.ID, appiam.ReqMeta{}) }()

	if res.Token.CreatedAt.IsZero() {
		t.Fatal("CreatedAt is the zero value: the INSERT did not read back the column default")
	}
	if res.Token.CreatedAt.Before(before) {
		t.Fatalf("CreatedAt %v predates the start of this test", res.Token.CreatedAt)
	}
	if res.Raw == "" || res.Token.Prefix == "" {
		t.Fatal("create returned no raw token or prefix")
	}
}

// Scope validation must fail with sentinels the delivery layer already maps.
//
// These used to be bare errors, so v1.fail fell through to its default case and
// answered 500 — telling somebody who asked for a scope that simply is not
// allowed that the server had broken, rather than which scope to drop.
func TestCreateAPITokenScopeErrorsAreTyped(t *testing.T) {
	svc, closeDB := newTokenService(t)
	defer closeDB()
	ctx := context.Background()
	actor := tokenIssuer(ctx, t, svc)

	if _, err := svc.CreateAPIToken(ctx, actor, "n", []string{"device:write"}, nil, appiam.ReqMeta{}); !errors.Is(err, iam.ErrTokenScope) {
		t.Fatalf("a write scope must fail with ErrTokenScope, got %v", err)
	}
	if _, err := svc.CreateAPIToken(ctx, actor, "n", []string{}, nil, appiam.ReqMeta{}); !errors.Is(err, iam.ErrInvalidInput) {
		t.Fatalf("empty scopes must fail with ErrInvalidInput, got %v", err)
	}
	if _, err := svc.CreateAPIToken(ctx, actor, "n", []string{"   "}, nil, appiam.ReqMeta{}); !errors.Is(err, iam.ErrInvalidInput) {
		t.Fatalf("whitespace-only scopes must fail with ErrInvalidInput, got %v", err)
	}
}

// Verify resolves a live token, refuses a revoked one, and never grants super
// admin — a token is a fixed list of permissions, and super admin means
// "everything, including permissions that do not exist yet".
func TestVerifyAPITokenLifecycle(t *testing.T) {
	svc, closeDB := newTokenService(t)
	defer closeDB()
	ctx := context.Background()
	actor := tokenIssuer(ctx, t, svc)

	res, err := svc.CreateAPIToken(ctx, actor, "integration-lifecycle", []string{"device:read"}, nil, appiam.ReqMeta{})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	claims, err := svc.VerifyAPIToken(ctx, res.Raw)
	if err != nil {
		t.Fatalf("verify fresh token: %v", err)
	}
	if claims.IsSuperAdmin {
		t.Fatal("an API token must never authenticate as super admin")
	}
	if claims.UserID != res.Token.ID {
		t.Fatal("claims must be attributed to the token, not to the human who issued it")
	}

	if err := svc.RevokeAPIToken(ctx, actor, res.Token.ID, appiam.ReqMeta{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.VerifyAPIToken(ctx, res.Raw); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("a revoked token must fail as invalid credentials, got %v", err)
	}
}

// An expired token must be refused, and it must be refused the same way a
// nonexistent one is.
func TestVerifyAPITokenRejectsExpired(t *testing.T) {
	svc, closeDB := newTokenService(t)
	defer closeDB()
	ctx := context.Background()
	actor := tokenIssuer(ctx, t, svc)

	// Creating an already-expired token is refused, so create one that expires
	// imminently and wait it out.
	soon := time.Now().Add(2 * time.Second)
	res, err := svc.CreateAPIToken(ctx, actor, "integration-expiry", []string{"device:read"}, &soon, appiam.ReqMeta{})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	defer func() { _ = svc.RevokeAPIToken(ctx, actor, res.Token.ID, appiam.ReqMeta{}) }()

	if _, err := svc.VerifyAPIToken(ctx, res.Raw); err != nil {
		t.Fatalf("token should still be valid before expiry: %v", err)
	}
	time.Sleep(3 * time.Second)
	if _, err := svc.VerifyAPIToken(ctx, res.Raw); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("an expired token must fail as invalid credentials, got %v", err)
	}
}
