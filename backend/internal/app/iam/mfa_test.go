package iam

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// --- MFA test doubles ---------------------------------------------------------

type fakeMFARepo struct {
	method   *iam.MFAMethod
	recovery map[string]bool // hash(hex) -> used
}

func newFakeMFARepo() *fakeMFARepo { return &fakeMFARepo{recovery: map[string]bool{}} }

func (f *fakeMFARepo) Get(_ context.Context, _ iam.ID) (*iam.MFAMethod, error) {
	if f.method == nil {
		return nil, iam.ErrMFANotEnrolled
	}
	cp := *f.method
	return &cp, nil
}
func (f *fakeMFARepo) Upsert(_ context.Context, m *iam.MFAMethod) error {
	cp := *m
	f.method = &cp
	return nil
}
func (f *fakeMFARepo) Confirm(_ context.Context, _ iam.ID, at time.Time) error {
	if f.method != nil {
		f.method.ConfirmedAt = &at
	}
	return nil
}
func (f *fakeMFARepo) Delete(_ context.Context, _ iam.ID) error {
	f.method = nil
	f.recovery = map[string]bool{}
	return nil
}
func (f *fakeMFARepo) ReplaceRecoveryCodes(_ context.Context, _ iam.ID, hashes [][]byte) error {
	f.recovery = map[string]bool{}
	for _, h := range hashes {
		f.recovery[string(h)] = false
	}
	return nil
}
func (f *fakeMFARepo) ConsumeRecoveryCode(_ context.Context, _ iam.ID, hash []byte, _ time.Time) (bool, error) {
	k := string(hash)
	used, ok := f.recovery[k]
	if !ok || used {
		return false, nil
	}
	f.recovery[k] = true
	return true, nil
}
func (f *fakeMFARepo) CountRecoveryCodes(_ context.Context, _ iam.ID) (int, error) {
	n := 0
	for _, used := range f.recovery {
		if !used {
			n++
		}
	}
	return n, nil
}

// fakeTOTP treats fixed codes as valid so the app flow can be tested without
// depending on wall-clock TOTP math (which is covered in the security package).
// good is the single login code; good followed by good2 is the accepted
// consecutive pair for enrollment.
type fakeTOTP struct{ good, good2 string }

func (f fakeTOTP) GenerateSecret() (string, error) { return "TESTSECRET234567", nil }
func (f fakeTOTP) Validate(_, code string) bool    { return code == f.good }
func (f fakeTOTP) ValidateConsecutive(_, code1, code2 string) bool {
	return code1 == f.good && code2 == f.good2
}
func (f fakeTOTP) ProvisioningURI(_, _, _ string) string { return "otpauth://totp/test" }

// identityCipher is a reversible no-op cipher for tests.
type identityCipher struct{}

func (identityCipher) Encrypt(p []byte) ([]byte, error) { return append([]byte("enc:"), p...), nil }
func (identityCipher) Decrypt(b []byte) ([]byte, error) {
	return bytes.TrimPrefix(b, []byte("enc:")), nil
}

// mfaHarness builds an MFA-enabled service over the base fakes.
type mfaHarness struct {
	*harness
	mfa *fakeMFARepo
}

func newMFAHarness(t *testing.T) *mfaHarness {
	t.Helper()
	base := newHarness(t)
	mfa := newFakeMFARepo()
	base.svc = NewService(Deps{
		Users: base.users, Orgs: base.orgs, Roles: fakeRoleRepo{}, Sessions: base.sessions,
		Hasher: base.hasher, Tokens: security.NewJWTIssuer("0123456789abcdef0123456789abcdef", "guardrail", 15*time.Minute),
		Refresh: security.NewRefreshGenerator(), Audit: nopAudit{}, Throttle: nopThrottle{},
		Clock:  fixedClock{t: base.now},
		Config: Config{MaxLoginFailures: 5, LockoutDuration: 15 * time.Minute, RefreshTTL: 720 * time.Hour},
		MFA:    mfa, TOTP: fakeTOTP{good: "123456", good2: "234567"}, Cipher: identityCipher{},
		MFAChal: security.NewMFAChallenger("0123456789abcdef0123456789abcdef", 5*time.Minute),
	})
	return &mfaHarness{harness: base, mfa: mfa}
}

func claimsFor(u *iam.User) iam.Claims {
	return iam.Claims{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email.String()}
}

func TestMFA_EnrollConfirmAndChallengeFlow(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()
	u := h.addUser(t, "mfa@acme.com", "supersecret-123")

	// Before enrollment, login issues tokens directly.
	pair, err := h.svc.Login(ctx, LoginInput{Email: "mfa@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.MFARequired || pair.AccessToken == "" {
		t.Fatal("expected direct token issue before MFA enrollment")
	}

	// Enroll + confirm.
	enr, err := h.svc.BeginTOTPEnrollment(ctx, claimsFor(u))
	if err != nil {
		t.Fatalf("begin enroll: %v", err)
	}
	if enr.Secret == "" || enr.ProvisioningURI == "" {
		t.Fatal("enrollment missing secret/uri")
	}
	codes, err := h.svc.ConfirmTOTPEnrollment(ctx, claimsFor(u), "123456", "234567")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("expected %d recovery codes, got %d", recoveryCodeCount, len(codes))
	}

	// Now login must return a challenge, not tokens.
	pair, err = h.svc.Login(ctx, LoginInput{Email: "mfa@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !pair.MFARequired || pair.MFAToken == "" || pair.AccessToken != "" {
		t.Fatalf("expected MFA challenge, got %+v", pair)
	}

	// Wrong code is rejected.
	if _, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{MFAToken: pair.MFAToken, Code: "000000"}); !errors.Is(err, iam.ErrMFAInvalidCode) {
		t.Fatalf("bad code err = %v, want ErrMFAInvalidCode", err)
	}

	// Correct TOTP completes the login.
	final, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{MFAToken: pair.MFAToken, Code: "123456"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if final.AccessToken == "" || final.RefreshToken == "" {
		t.Fatal("expected tokens after successful MFA")
	}
}

func TestMFA_RecoveryCodeSingleUse(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()
	u := h.addUser(t, "rec@acme.com", "supersecret-123")

	if _, err := h.svc.BeginTOTPEnrollment(ctx, claimsFor(u)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	codes, err := h.svc.ConfirmTOTPEnrollment(ctx, claimsFor(u), "123456", "234567")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// Get a fresh challenge.
	pair, _ := h.svc.Login(ctx, LoginInput{Email: "rec@acme.com", Password: "supersecret-123"})

	// Using a recovery code completes the login.
	if _, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{MFAToken: pair.MFAToken, Code: codes[0]}); err != nil {
		t.Fatalf("recovery verify: %v", err)
	}

	// The same recovery code cannot be reused.
	pair2, _ := h.svc.Login(ctx, LoginInput{Email: "rec@acme.com", Password: "supersecret-123"})
	if _, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{MFAToken: pair2.MFAToken, Code: codes[0]}); !errors.Is(err, iam.ErrMFAInvalidCode) {
		t.Fatalf("reused recovery code err = %v, want ErrMFAInvalidCode", err)
	}

	// A different, unused code still works.
	if _, err := h.svc.VerifyMFA(ctx, MFAVerifyInput{MFAToken: pair2.MFAToken, Code: codes[1]}); err != nil {
		t.Fatalf("second recovery code: %v", err)
	}
}

func TestMFA_DisableRestoresDirectLogin(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()
	u := h.addUser(t, "off@acme.com", "supersecret-123")
	if _, err := h.svc.BeginTOTPEnrollment(ctx, claimsFor(u)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := h.svc.ConfirmTOTPEnrollment(ctx, claimsFor(u), "123456", "234567"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := h.svc.DisableMFA(ctx, claimsFor(u), "000000"); !errors.Is(err, iam.ErrMFAInvalidCode) {
		t.Fatalf("disable with bad code err = %v, want ErrMFAInvalidCode", err)
	}
	if err := h.svc.DisableMFA(ctx, claimsFor(u), "123456"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	pair, err := h.svc.Login(ctx, LoginInput{Email: "off@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.MFARequired || pair.AccessToken == "" {
		t.Fatal("expected direct login after MFA disabled")
	}
}

// Losing the authenticator must not mean losing the ability to turn MFA off.
// The server has always accepted a recovery code here (DisableMFA goes through
// checkSecondFactor) — this pins that, because the console quietly did not: it
// ran the field through a digits-only cleaner, so a recovery code like
// "a1b2c-3d4e5" became "12345" and the confirm button never enabled. The result
// was a permanent lockout for exactly the person recovery codes exist to save.
func TestMFA_DisableAcceptsRecoveryCode(t *testing.T) {
	h := newMFAHarness(t)
	ctx := context.Background()
	u := h.addUser(t, "lost-phone@acme.com", "supersecret-123")
	if _, err := h.svc.BeginTOTPEnrollment(ctx, claimsFor(u)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	codes, err := h.svc.ConfirmTOTPEnrollment(ctx, claimsFor(u), "123456", "234567")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if len(codes) == 0 {
		t.Fatal("expected recovery codes at enrollment")
	}
	// No TOTP available — only the paper codes.
	if err := h.svc.DisableMFA(ctx, claimsFor(u), codes[0]); err != nil {
		t.Fatalf("disable with a recovery code: %v", err)
	}
	// And MFA really is off: login no longer challenges.
	pair, err := h.svc.Login(ctx, LoginInput{Email: "lost-phone@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.MFAToken != "" {
		t.Error("still challenged for MFA after disabling with a recovery code")
	}
}

// The server normalises case/dashes/spaces, so a code typed the way a human
// copies it off paper must work.
func TestMFA_RecoveryCodeAcceptedInAnyFormatting(t *testing.T) {
	for name, mangle := range map[string]func(string) string{
		"as issued":  func(s string) string { return s },
		"uppercased": strings.ToUpper,
		"no dashes":  func(s string) string { return strings.ReplaceAll(s, "-", "") },
		"padded":     func(s string) string { return "  " + s + "  " },
	} {
		t.Run(name, func(t *testing.T) {
			h := newMFAHarness(t)
			ctx := context.Background()
			u := h.addUser(t, "fmt@acme.com", "supersecret-123")
			if _, err := h.svc.BeginTOTPEnrollment(ctx, claimsFor(u)); err != nil {
				t.Fatal(err)
			}
			codes, err := h.svc.ConfirmTOTPEnrollment(ctx, claimsFor(u), "123456", "234567")
			if err != nil {
				t.Fatal(err)
			}
			if err := h.svc.DisableMFA(ctx, claimsFor(u), mangle(codes[0])); err != nil {
				t.Errorf("recovery code %q rejected: %v", mangle(codes[0]), err)
			}
		})
	}
}
