//go:build integration

package test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// TestIntegration_MFARepo exercises the MFA repository against the live database:
// upsert → confirm → recovery-code replace → single-use consume.
func TestIntegration_MFARepo(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	repo := postgres.NewMFARepo(pg)

	// A real user row is required (FK). Create one in the default org.
	userID := uuid.New()
	users := postgres.NewUserRepo(pg)
	if err := users.Create(ctx, iam.TenantScope{OrganizationID: defaultOrgID}, &iam.User{
		ID: userID, OrganizationID: defaultOrgID, Email: iam.NewEmail("mfa-" + userID.String()[:8] + "@acme.com"),
		Username: "mfauser", PasswordHash: "x", AuthProvider: iam.ProviderLocal, Status: "active",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Not enrolled yet.
	if _, err := repo.Get(ctx, userID); err == nil {
		t.Fatal("expected ErrMFANotEnrolled before enrollment")
	}

	// Enroll (unconfirmed) then confirm.
	if err := repo.Upsert(ctx, &iam.MFAMethod{UserID: userID, Type: iam.MFATypeTOTP, Secret: []byte("encrypted-secret")}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	m, err := repo.Get(ctx, userID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if m.Confirmed() {
		t.Fatal("method should be unconfirmed after upsert")
	}
	if err := repo.Confirm(ctx, userID, time.Now()); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if m, _ = repo.Get(ctx, userID); !m.Confirmed() {
		t.Fatal("method should be confirmed")
	}

	// Recovery codes: replace with two, consume one twice.
	h1 := sha256.Sum256([]byte("code-one"))
	h2 := sha256.Sum256([]byte("code-two"))
	if err := repo.ReplaceRecoveryCodes(ctx, userID, [][]byte{h1[:], h2[:]}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if n, _ := repo.CountRecoveryCodes(ctx, userID); n != 2 {
		t.Fatalf("expected 2 codes, got %d", n)
	}
	ok, err := repo.ConsumeRecoveryCode(ctx, userID, h1[:], time.Now())
	if err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}
	ok, _ = repo.ConsumeRecoveryCode(ctx, userID, h1[:], time.Now())
	if ok {
		t.Fatal("recovery code must not be consumable twice")
	}
	if n, _ := repo.CountRecoveryCodes(ctx, userID); n != 1 {
		t.Fatalf("expected 1 code left, got %d", n)
	}

	// Delete removes enrollment.
	if err := repo.Delete(ctx, userID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.Get(ctx, userID); err == nil {
		t.Fatal("expected not-enrolled after delete")
	}
}
