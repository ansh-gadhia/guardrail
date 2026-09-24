package iam

import (
	"context"
	"errors"
	"sync"
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
	audit    *captureAudit
	hasher   *security.Argon2Hasher
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	users := newFakeUserRepo()
	sessions := newFakeSessionRepo(users)
	orgs := newFakeOrgRepo()
	rec := &captureAudit{}
	hasher := security.NewArgon2Hasher(security.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc := NewService(Deps{
		Users: users, Orgs: orgs, Roles: fakeRoleRepo{}, Sessions: sessions,
		Hasher: hasher, Tokens: security.NewJWTIssuer("0123456789abcdef0123456789abcdef", "guardrail", 15*time.Minute),
		Refresh: security.NewRefreshGenerator(), Audit: rec, Throttle: nopThrottle{},
		Clock:  fixedClock{t: now},
		Config: Config{MaxLoginFailures: 5, LockoutDuration: 15 * time.Minute, RefreshTTL: 720 * time.Hour},
	})
	return &harness{svc: svc, users: users, sessions: sessions, orgs: orgs, audit: rec, hasher: hasher, now: now}
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

	if err := h.svc.Logout(ctx, pair.RefreshToken, ReqMeta{}, false); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := h.svc.Refresh(ctx, pair.RefreshToken, ReqMeta{}); err == nil {
		t.Fatal("expected refresh to fail after logout")
	}
}

// harnessAt builds a service whose clock can be moved, with the console's real
// session policy: a twelve-hour lifetime and a thirty-minute idle timeout.
func harnessAt(t *testing.T) (*harness, *movableClock) {
	t.Helper()
	h := newHarness(t)
	clk := &movableClock{t: h.now}
	h.svc.clock = clk
	h.svc.cfg.RefreshTTL = 12 * time.Hour
	h.svc.cfg.IdleTimeout = 30 * time.Minute
	return h, clk
}

type movableClock struct{ t time.Time }

func (c *movableClock) Now() time.Time { return c.t }

// The complaint this fixes: open the site after ten days and still be signed
// in. A browser that restored its session cookie must not be enough.
func TestRefresh_SignsOutAfterTheBrowserWasClosed(t *testing.T) {
	h, clk := harnessAt(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, err := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatal(err)
	}

	clk.t = clk.t.Add(10 * 24 * time.Hour) // ten days later
	_, err = h.svc.Refresh(ctx, pair.RefreshToken, ReqMeta{})
	if err == nil {
		t.Fatal("a token untouched for ten days still refreshed; the login survived the browser")
	}
	if !errors.Is(err, iam.ErrSessionIdle) && !errors.Is(err, iam.ErrSessionLifetime) {
		t.Fatalf("err = %v, want a policy sign-out", err)
	}
}

// Closed for longer than the idle timeout, even inside the lifetime.
func TestRefresh_IdleTimeoutSignsOut(t *testing.T) {
	h, clk := harnessAt(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	clk.t = clk.t.Add(31 * time.Minute)
	if _, err := h.svc.Refresh(ctx, pair.RefreshToken, ReqMeta{}); !errors.Is(err, iam.ErrSessionIdle) {
		t.Fatalf("31 minutes idle: err = %v, want ErrSessionIdle", err)
	}
	// And it is recorded as the system signing somebody out.
	var found bool
	for _, e := range h.audit.events {
		if e.Action == "auth.session_expired" && e.Detail["reason"] == "idle" {
			found = true
		}
	}
	if !found {
		t.Error("an idle sign-out was not audited")
	}
}

// Somebody actively using the console is never signed out for being idle: an
// open console refreshes every access-token lifetime, well inside the timeout.
func TestRefresh_ActiveUseIsNotIdle(t *testing.T) {
	h, clk := harnessAt(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	tok := pair.RefreshToken
	for i := 0; i < 20; i++ { // five hours of refreshes, fifteen minutes apart
		clk.t = clk.t.Add(15 * time.Minute)
		p, err := h.svc.Refresh(ctx, tok, ReqMeta{})
		if err != nil {
			t.Fatalf("refresh %d at +%s of steady use: %v", i+1, time.Duration(i+1)*15*time.Minute, err)
		}
		tok = p.RefreshToken
	}
}

// Rotation must not extend a login. This is the bug that made it immortal: every
// refresh used to issue a token good for another full lifetime.
func TestRefresh_RotationDoesNotExtendTheLifetime(t *testing.T) {
	h, clk := harnessAt(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	login := clk.t
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	tok := pair.RefreshToken
	var lastErr error
	for i := 0; i < 60; i++ { // keep refreshing every 15 minutes, for 15 hours
		clk.t = clk.t.Add(15 * time.Minute)
		p, err := h.svc.Refresh(ctx, tok, ReqMeta{})
		if err != nil {
			lastErr = err
			break
		}
		if !p.RefreshExpiresAt.Equal(login.Add(12 * time.Hour)) {
			t.Fatalf("rotation moved the deadline to %s; it must stay at sign-in + 12h (%s)",
				p.RefreshExpiresAt, login.Add(12*time.Hour))
		}
		tok = p.RefreshToken
	}
	if !errors.Is(lastErr, iam.ErrSessionLifetime) {
		t.Fatalf("constant use for 15h: err = %v, want ErrSessionLifetime at the 12h mark", lastErr)
	}
	if got := clk.t.Sub(login); got > 12*time.Hour+15*time.Minute {
		t.Fatalf("signed out only after %s of use; the lifetime is 12h", got)
	}
}

// A login issued under the old sliding thirty days is capped by its first
// refresh after the upgrade, rather than living out its thirty days.
func TestRefresh_CapsALegacyThirtyDayToken(t *testing.T) {
	h, clk := harnessAt(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	h.svc.cfg.RefreshTTL = 720 * time.Hour // issued under the old policy
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})
	h.svc.cfg.RefreshTTL = 12 * time.Hour // upgraded

	clk.t = clk.t.Add(10 * time.Minute)
	p, err := h.svc.Refresh(ctx, pair.RefreshToken, ReqMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if want := clk.t.Add(12 * time.Hour); p.RefreshExpiresAt.After(want) {
		t.Fatalf("a legacy token kept a deadline of %s; it should be capped at %s", p.RefreshExpiresAt, want)
	}
}

// One sign-out is one event. A browser waking from sleep can send the request
// twice at once — its idle clock and a refused request both notice — and both
// were recorded, as "GuardRail signed out" twice, because the event carried an
// id and no name.
func TestLogout_RecordedOnceAndNamed(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.svc.Logout(ctx, pair.RefreshToken, ReqMeta{}, false)
		}()
	}
	wg.Wait()

	got := h.audit.find("auth.logout", "")
	if len(got) != 1 {
		t.Fatalf("recorded %d sign-outs for one sign-in, want 1", len(got))
	}
	if got[0].ActorEmail != "admin@acme.com" {
		t.Fatalf("sign-out credited to %q, want the person who signed out", got[0].ActorEmail)
	}
}

// A browser that signs itself out for inactivity says so, and the log says it
// the way the server's own idle check does — not as a plain sign-out.
func TestLogout_IdleFromTheBrowserReadsAsIdle(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "admin@acme.com", "supersecret-123")
	ctx := context.Background()
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "admin@acme.com", Password: "supersecret-123"})

	if err := h.svc.Logout(ctx, pair.RefreshToken, ReqMeta{}, true); err != nil {
		t.Fatal(err)
	}
	if n := len(h.audit.find("auth.session_expired", "idle")); n != 1 {
		t.Fatalf("idle sign-outs recorded: %d, want 1", n)
	}
	if n := len(h.audit.find("auth.logout", "")); n != 0 {
		t.Fatalf("also recorded %d plain sign-outs", n)
	}
}
