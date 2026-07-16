package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// harness builds a Service backed by fakes plus real crypto adapters.
type harness struct {
	svc      *Service
	users    *fakeUserRepo
	sessions *fakeSessionRepo
	orgs     *fakeOrgRepo
	hasher   *security.Argon2Hasher
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	users := newFakeUserRepo()
	sessions := newFakeSessionRepo(users)
	orgs := newFakeOrgRepo()
	hasher := security.NewArgon2Hasher(security.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc := NewService(Deps{
		Users: users, Orgs: orgs, Roles: fakeRoleRepo{}, Sessions: sessions,
		Hasher: hasher, Tokens: security.NewJWTIssuer("0123456789abcdef0123456789abcdef", "guardrail", 15*time.Minute),
		Refresh: security.NewRefreshGenerator(), Audit: nopAudit{}, Throttle: nopThrottle{},
		Clock:  fixedClock{t: now},
		Config: Config{MaxLoginFailures: 5, LockoutDuration: 15 * time.Minute, RefreshTTL: 720 * time.Hour},
	})
	return &harness{svc: svc, users: users, sessions: sessions, orgs: orgs, hasher: hasher, now: now}
}

func (h *harness) addUser(t *testing.T, email, password string) *iam.User {
	t.Helper()
	return h.addUserInOrg(t, iam.NewID(), email, password)
}

// addUserInOrg places a user in a specific organization, for the cases where the
// test needs the user and an org fixture to line up.
func (h *harness) addUserInOrg(t *testing.T, orgID iam.ID, email, password string) *iam.User {
	t.Helper()
	hash, err := h.hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := &iam.User{
		ID: iam.NewID(), OrganizationID: orgID, Email: iam.NewEmail(email),
		Username: "u", PasswordHash: hash, AuthProvider: iam.ProviderLocal, Status: "active",
	}
	h.users.add(u)
	return u
}

func TestLogin_Success(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")

	pair, err := h.svc.Login(context.Background(), LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected both tokens issued")
	}
	if pair.Principal.Email != "admin@acme.com" {
		t.Fatalf("principal email = %q", pair.Principal.Email)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	_, err := h.svc.Login(context.Background(), LoginInput{Email: "admin@acme.com", Password: "nope"})
	if !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.Login(context.Background(), LoginInput{Email: "ghost@acme.com", Password: "whatever-1234"})
	if !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials (no user enumeration)", err)
	}
}

func TestLogin_LockoutAfterThreshold(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()

	// 5 failures should lock the account.
	for i := 0; i < 5; i++ {
		if _, err := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "bad"}); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	// 6th attempt — even with the correct password — is locked out.
	_, err := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})
	if !errors.Is(err, iam.ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked", err)
	}
}

func TestLogin_AmbiguousEmailRequiresOrg(t *testing.T) {
	h := newHarness(t)
	// Two users share an email across different orgs.
	h.addUser(t, "dup@acme.com", "supersecret-123")
	h.addUser(t, "dup@acme.com", "supersecret-456")
	_, err := h.svc.Login(context.Background(), LoginInput{Email: "dup@acme.com", Password: "supersecret-123"})
	if !errors.Is(err, iam.ErrEmailAmbiguous) {
		t.Fatalf("err = %v, want ErrEmailAmbiguous", err)
	}
}

func TestRefresh_RotatesAndDetectsReuse(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()

	pair, err := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	original := pair.RefreshToken

	// First refresh rotates to a new token.
	rotated, err := h.svc.Refresh(ctx, original, ReqMeta{})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == original {
		t.Fatal("refresh did not rotate the token")
	}

	// Reusing the original (now-revoked) token is detected and kills the family.
	if _, err := h.svc.Refresh(ctx, original, ReqMeta{}); !errors.Is(err, iam.ErrRefreshReuse) {
		t.Fatalf("reuse err = %v, want ErrRefreshReuse", err)
	}
	// The rotated token is now revoked too (whole family killed), so presenting
	// it also trips reuse detection rather than succeeding.
	if _, err := h.svc.Refresh(ctx, rotated.RefreshToken, ReqMeta{}); !errors.Is(err, iam.ErrRefreshReuse) {
		t.Fatalf("post-reuse err = %v, want ErrRefreshReuse", err)
	}
}

func TestLogout_RevokesFamily(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	if err := h.svc.Logout(ctx, pair.RefreshToken, ReqMeta{}); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := h.svc.Refresh(ctx, pair.RefreshToken, ReqMeta{}); err == nil {
		t.Fatal("expected refresh to fail after logout")
	}
}
