//go:build integration

// KEK rotation (SECURITY_AUDIT/01-findings.md H5).
//
//	GUARDRAIL_TEST_DSN=... GUARDRAIL_TEST_MASTER_KEY=... \
//	  go test -tags=integration ./test/ -run TestKEKRotation
package test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	appvault "github.com/guardrail/guardrail/internal/app/vault"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// A full rotation, end to end, on rows this test creates and removes.
//
// The property under test is the one that was broken: changing the master key
// used to produce a different key under the SAME id "env:1", so every row
// became unopenable with no warning. Now the id follows the key, the old key
// stays resolvable while it is configured, and rotation moves rows across.
func TestKEKRotationMovesSecretsOntoTheNewKey(t *testing.T) {
	db, done := newPG(t)
	defer done()
	ctx := context.Background()

	const oldMaster = "rotation-test-old-master-key-32+bytes"
	const newMaster = "rotation-test-new-master-key-32+bytes"

	oldKeys, err := security.NewEnvKeyProvider(oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := security.NewEnvKeyProvider(newMaster)
	if err != nil {
		t.Fatal(err)
	}
	oldID, _, _ := oldKeys.Active()
	newIDUp, _, _ := newKeys.Active()

	// Both registry cleanups are registered HERE, before any credential is
	// tracked. t.Cleanup is LIFO, so anything registered later runs first — and
	// a key cleanup that runs before the credential purge finds its row still
	// referenced and correctly declines to delete it. Registering up front puts
	// them last, which is where they belong.
	trackKEK(t, oldID)
	trackKEK(t, newIDUp)
	oldEnc := security.NewEnvelopeEncryptor(oldKeys)
	repo := postgres.NewCredentialRepo(db)

	// The old key has to be registered, or the foreign key refuses the insert —
	// which is itself the check that RegisterKEK is wired correctly.
	if err := repo.RegisterKEK(ctx, oldID, "env"); err != nil {
		t.Fatalf("register old kek: %v", err)
	}

	const secret = "rotation-test-device-password"
	credID := uuid.New()
	sealed, err := oldEnc.Seal([]byte(secret), domvault.CredentialAAD(defaultOrgID, credID))
	if err != nil {
		t.Fatal(err)
	}
	cred := &domvault.Credential{
		ID: credID, OrganizationID: defaultOrgID, Name: "rotation-probe",
		Type: domvault.TypePassword, Username: "probe",
		Injection: domvault.InjectForm, Sealed: sealed,
	}
	trackCredential(t, cred.ID)
	vScope := domvault.Scope{OrganizationID: defaultOrgID}
	if err := repo.Create(ctx, vScope, cred); err != nil {
		t.Fatalf("create: %v", err)
	}
	if sealed.KEKID != oldID {
		t.Fatalf("sealed under %q, expected the derived id %q", sealed.KEKID, oldID)
	}

	// --- the rotation ----------------------------------------------------
	rotKeys, err := security.NewEnvKeyProviderWithPrevious(newMaster, oldMaster)
	if err != nil {
		t.Fatal(err)
	}
	newID, _, _ := rotKeys.Active()
	if newID == oldID {
		t.Fatal("a different master key produced the same KEK id")
	}
	if rotKeys.Previous() != oldID {
		t.Fatalf("Previous() = %q, want %q", rotKeys.Previous(), oldID)
	}
	if err := repo.RegisterKEK(ctx, newID, "env"); err != nil {
		t.Fatalf("register new kek: %v", err)
	}

	rotSvc := appvault.NewService(repo, security.NewEnvelopeEncryptor(rotKeys), nil)
	before, err := repo.CountByKEK(ctx, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("nothing under the old key to rotate")
	}

	n, stranded, err := rotSvc.RotateKEK(ctx, oldID, 50)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != before {
		t.Errorf("rotated %d of %d (%d stranded)", n, before, stranded)
	}
	if stranded != 0 {
		t.Errorf("%d row(s) reported unopenable; this test seals them all itself", stranded)
	}
	if left, _ := repo.CountByKEK(ctx, oldID); left != 0 {
		t.Errorf("%d row(s) still under the old key", left)
	}

	// --- the secret survived, and is still bound -------------------------
	got, err := repo.GetByID(ctx, vScope, credID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sealed.KEKID != newID {
		t.Fatalf("row still names %q, want %q", got.Sealed.KEKID, newID)
	}
	newEnc := security.NewEnvelopeEncryptor(rotKeys)
	plaintext, err := newEnc.Open(got.Sealed, domvault.CredentialAAD(defaultOrgID, credID))
	if err != nil {
		t.Fatalf("the rotated secret will not open under the new key: %v", err)
	}
	if string(plaintext) != secret {
		t.Fatalf("plaintext changed across rotation: %q", plaintext)
	}
	// Rotation must NOT disturb the AAD binding — it re-wraps the DEK only.
	if got.Sealed.AADVersion != domvault.AADCredentialV1 {
		t.Errorf("rotation dropped the AAD version: %d", got.Sealed.AADVersion)
	}
	if _, e := newEnc.Open(got.Sealed, domvault.CredentialAAD(defaultOrgID, uuid.New())); e == nil {
		t.Error("after rotation the secret opened under another credential's identity")
	}

	// --- and the OLD key can no longer open it ---------------------------
	if _, e := oldEnc.Open(got.Sealed, domvault.CredentialAAD(defaultOrgID, credID)); e == nil {
		t.Error("the superseded key still opens the rotated secret")
	}
}

// Before this fix, a changed master key produced a different KEK under the same
// id, and every row failed to open with a corrupt-looking authentication error.
// Now it fails as an UNKNOWN KEY, which is a diagnosable fact.
func TestChangedMasterKeyIsDiagnosable(t *testing.T) {
	a, err := security.NewEnvKeyProvider(strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	b, err := security.NewEnvKeyProvider(strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	idA, _, _ := a.Active()

	// b has never heard of a's key.
	if _, err := b.Get(idA); err == nil {
		t.Fatal("a provider resolved a key id it does not hold")
	} else if !strings.Contains(err.Error(), "unknown KEK id") {
		t.Errorf("error should name the unknown id, got: %v", err)
	}
}

// trackKEK removes a registry row at the end of the test, but only when nothing
// references it — a key that ended up sealing something is evidence, not litter.
//
// It opens its OWN connection inside the cleanup rather than reusing the shared
// pool: t.Cleanup is LIFO and rawPool registers pool.Close, so a cleanup
// registered afterwards would find the pool already shut. That is exactly how
// the first version of this silently did nothing.
func trackKEK(t *testing.T, id string) {
	t.Helper()
	// The OWNER dsn, not the app one. guardrail_app has INSERT/SELECT/UPDATE on
	// encryption_keys but deliberately no DELETE: removing a key row would
	// orphan every credential that names it through the foreign key. That is the
	// right privilege for the application and the wrong one for a test tidying
	// up after itself, so this skips rather than pretending to clean.
	dsn := os.Getenv("GUARDRAIL_TEST_OWNER_DSN")
	t.Cleanup(func() {
		if dsn == "" {
			t.Logf("GUARDRAIL_TEST_OWNER_DSN not set; leaving registry row %s behind", id)
			return
		}
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Logf("kek cleanup: connect: %v", err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, "SET app.is_super_admin = 'on'"); err != nil {
			t.Logf("kek cleanup: guc: %v", err)
			return
		}
		if _, err := conn.Exec(ctx, `
			DELETE FROM encryption_keys ek
			WHERE ek.id = $1
			  AND NOT EXISTS (SELECT 1 FROM credentials c WHERE c.kek_id = ek.id)`, id); err != nil {
			t.Logf("kek cleanup: delete %s: %v", id, err)
		}
	})
}
