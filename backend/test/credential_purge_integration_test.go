//go:build integration

// Credential retention (SECURITY_AUDIT/01-findings.md M9).
//
//	GUARDRAIL_TEST_DSN=... GUARDRAIL_TEST_MASTER_KEY=... \
//	  go test -tags=integration ./test/ -run TestCredentialPurge
package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	appvault "github.com/guardrail/guardrail/internal/app/vault"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// purgeFixture creates a credential, binds it to a device, then soft-deletes it
// with a deleted_at far enough in the past to be due.
func purgeFixture(t *testing.T, ctx context.Context, repo *postgres.CredentialRepo,
	enc domvault.Encryptor, raw *pgxpool.Pool, age time.Duration) uuid.UUID {
	t.Helper()
	credID := uuid.New()
	sealed, err := enc.Seal([]byte("purge-probe-secret"), domvault.CredentialAAD(defaultOrgID, credID))
	if err != nil {
		t.Fatal(err)
	}
	c := &domvault.Credential{
		ID: credID, OrganizationID: defaultOrgID, Name: "purge-probe",
		Type: domvault.TypePassword, Username: "probe",
		Injection: domvault.InjectForm, Sealed: sealed,
	}
	trackCredential(t, credID)
	if err := repo.Create(ctx, domvault.Scope{OrganizationID: defaultOrgID}, c); err != nil {
		t.Fatalf("create: %v", err)
	}
	if age > 0 {
		if err := rawTx(t, raw, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE credentials SET deleted_at=$2 WHERE id=$1`,
				credID, time.Now().Add(-age))
			return e
		}); err != nil {
			t.Fatalf("soft delete: %v", err)
		}
	}
	return credID
}

func TestCredentialPurgeRemovesExpiredSecrets(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	kp, err := security.NewEnvKeyProvider(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	enc := security.NewEnvelopeEncryptor(kp)
	repo := postgres.NewCredentialRepo(db)
	svc := appvault.NewService(repo, enc, nil)
	// credentials.kek_id is a foreign key, so the derived id has to be in the
	// registry before anything can be sealed under it. The API does this at
	// startup; a test that constructs its own repo has to do it too.
	activeID, _, _ := kp.Active()
	trackKEK(t, activeID)
	if err := repo.RegisterKEK(ctx, activeID, "env"); err != nil {
		t.Fatalf("register kek: %v", err)
	}

	// Deleted 60 days ago: due under a 30-day retention.
	old := purgeFixture(t, ctx, repo, enc, raw, 60*24*time.Hour)

	n, err := svc.PurgeDeletedCredentials(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n == 0 {
		t.Fatal("nothing was purged although a credential was long past retention")
	}

	// The row, and its ciphertext, must be gone — not merely hidden again.
	var remaining int
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id=$1`, old).Scan(&remaining)
	}); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("the credential row survived the purge")
	}
}

// The property that matters most: a LIVE credential must never be reachable by
// this code path, whatever it is asked.
func TestCredentialPurgeNeverTouchesLiveCredentials(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	kp, err := security.NewEnvKeyProvider(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	enc := security.NewEnvelopeEncryptor(kp)
	repo := postgres.NewCredentialRepo(db)
	svc := appvault.NewService(repo, enc, nil)
	// credentials.kek_id is a foreign key, so the derived id has to be in the
	// registry before anything can be sealed under it. The API does this at
	// startup; a test that constructs its own repo has to do it too.
	activeID, _, _ := kp.Active()
	trackKEK(t, activeID)
	if err := repo.RegisterKEK(ctx, activeID, "env"); err != nil {
		t.Fatalf("register kek: %v", err)
	}

	live := purgeFixture(t, ctx, repo, enc, raw, 0) // never deleted

	// A retention of one nanosecond makes everything eligible by age. The live
	// row must still be untouched, because age is not the only condition.
	if _, err := svc.PurgeDeletedCredentials(ctx, time.Nanosecond); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := repo.GetByID(ctx, domvault.Scope{OrganizationID: defaultOrgID}, live); err != nil {
		t.Fatalf("a live credential was destroyed by the retention sweep: %v", err)
	}

	// And HardDelete refuses it directly, which is the guard that matters if a
	// caller ever passes the wrong id.
	if err := repo.HardDelete(ctx, live); err == nil {
		t.Fatal("HardDelete removed a credential that was never soft-deleted")
	}
	if _, err := repo.GetByID(ctx, domvault.Scope{OrganizationID: defaultOrgID}, live); err != nil {
		t.Fatalf("HardDelete damaged a live credential even while refusing it: %v", err)
	}
}

// Retention of zero must disable the sweep, not mean "purge everything now".
func TestCredentialPurgeZeroRetentionIsOff(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	kp, err := security.NewEnvKeyProvider(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	enc := security.NewEnvelopeEncryptor(kp)
	repo := postgres.NewCredentialRepo(db)
	svc := appvault.NewService(repo, enc, nil)
	// credentials.kek_id is a foreign key, so the derived id has to be in the
	// registry before anything can be sealed under it. The API does this at
	// startup; a test that constructs its own repo has to do it too.
	activeID, _, _ := kp.Active()
	trackKEK(t, activeID)
	if err := repo.RegisterKEK(ctx, activeID, "env"); err != nil {
		t.Fatalf("register kek: %v", err)
	}

	old := purgeFixture(t, ctx, repo, enc, raw, 365*24*time.Hour)

	n, err := svc.PurgeDeletedCredentials(ctx, 0)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 0 {
		t.Fatalf("a zero retention purged %d credential(s); it must disable the sweep", n)
	}
	var still int
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id=$1`, old).Scan(&still)
	}); err != nil {
		t.Fatal(err)
	}
	if still != 1 {
		t.Fatal("a zero retention destroyed a credential")
	}
}
