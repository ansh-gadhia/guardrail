//go:build integration

// Credential AAD binding (SECURITY_AUDIT/01-findings.md C1, first half).
//
//	GUARDRAIL_TEST_DSN=... GUARDRAIL_TEST_MASTER_KEY=<the deployment's key> \
//	  go test -tags=integration ./test/ -run TestCredentialAAD
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

// masterKey is the deployment's real key, because these tests re-seal rows that
// were sealed with it. Without it the re-seal cannot open anything.
func masterKey(t *testing.T) string {
	t.Helper()
	k := os.Getenv("GUARDRAIL_TEST_MASTER_KEY")
	if k == "" {
		t.Skip("GUARDRAIL_TEST_MASTER_KEY not set")
	}
	return k
}

// The upgrade must not take existing credentials offline. Every secret sealed
// before 0036 has no tag over any associated data, so it has to keep opening
// under the version recorded on its row.
func TestCredentialAADLegacyRowsKeepWorkingThenConvert(t *testing.T) {
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

	// A genuine pre-0036 row of our own, so a clean database has something to
	// convert instead of skipping the conversion entirely.
	seedLegacyCredential(t, db)

	var legacy int
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM credentials WHERE aad_version=0 AND deleted_at IS NULL`).Scan(&legacy)
	}); err != nil {
		t.Fatal(err)
	}
	if legacy == 0 {
		t.Skip("no legacy credentials left to convert")
	}

	// Every legacy row THIS DEPLOYMENT CAN OPEN must open before conversion, or
	// live sessions break. A row sealed under a different master key was already
	// unreadable and is counted separately.
	rows, err := repo.ListByAADVersion(ctx, domvault.AADNone, 500)
	if err != nil {
		t.Fatal(err)
	}
	openable := 0
	for i := range rows {
		if _, e := enc.Open(rows[i].Sealed, nil); e == nil {
			openable++
		}
	}

	n, stuck, err := svc.ReSealLegacyCredentials(ctx, 100)
	if err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if n != openable {
		t.Errorf("re-sealed %d, %d were openable", n, openable)
	}
	if stuck != len(rows)-openable {
		t.Errorf("reported %d unopenable, %d actually were", stuck, len(rows)-openable)
	}
	if stuck > 0 {
		t.Logf("%d credential(s) cannot be opened by this deployment's key and were left alone", stuck)
	}

	// Idempotent: a second run converts nothing new.
	if again, _, e := svc.ReSealLegacyCredentials(ctx, 100); e != nil || again != 0 {
		t.Errorf("second re-seal converted %d (err %v), want 0", again, e)
	}

	// And every converted row opens under its own identity, and ONLY its own.
	converted, err := repo.ListByAADVersion(ctx, domvault.AADCredentialV1, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(converted) == 0 {
		t.Fatal("nothing is marked as bound after conversion")
	}
	for i := range converted {
		c := &converted[i]
		if _, e := enc.Open(c.Sealed, domvault.CredentialAAD(c.OrganizationID, c.ID)); e != nil {
			t.Fatalf("a converted credential cannot open its own secret: %v", e)
		}
		// The attack: the same ciphertext under a different credential's identity.
		if _, e := enc.Open(c.Sealed, domvault.CredentialAAD(c.OrganizationID, uuid.New())); e == nil {
			t.Fatal("a converted secret opened under another credential's id")
		}
		if _, e := enc.Open(c.Sealed, domvault.CredentialAAD(uuid.New(), c.ID)); e == nil {
			t.Fatal("a converted secret opened under another organization")
		}
	}
}

// Resolution must still work after conversion — the end-to-end check that the
// AAD the resolve path computes is the one the re-seal job bound in. A mismatch
// here is how a security upgrade silently breaks every device.
func TestCredentialAADResolveStillWorksAfterConversion(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	kp, err := security.NewEnvKeyProvider(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	enc := security.NewEnvelopeEncryptor(kp)
	signer, err := security.NewBindingSigner(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewCredentialRepo(db).WithBindingSigner(signer)
	svc := appvault.NewService(repo, enc, nil)

	// One legacy credential and one live binding of our own: the conversion has
	// something to convert and the resolve loop something to resolve, on a clean
	// database as well as a populated one.
	seedLegacyCredential(t, db)
	seedBinding(t, db)

	if _, _, err := svc.ReSealLegacyCredentials(ctx, 100); err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if _, err := repo.SignUnsignedBindings(ctx); err != nil {
		t.Fatalf("sign bindings: %v", err)
	}

	type pair struct{ dev, org uuid.UUID }
	var all []pair
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT dc.device_id, c.organization_id
			FROM device_credentials dc
			JOIN credentials c ON c.id = dc.credential_id
			JOIN devices d ON d.id = dc.device_id
			WHERE dc.user_id IS NULL AND c.deleted_at IS NULL AND d.deleted_at IS NULL`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p pair
			if e := rows.Scan(&p.dev, &p.org); e != nil {
				return e
			}
			all = append(all, p)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Skip("no live device bindings to resolve")
	}

	for _, p := range all {
		res, err := repo.ResolveForDevice(ctx, domvault.Scope{OrganizationID: p.org}, p.dev, uuid.Nil)
		if err != nil {
			t.Fatalf("device %s stopped resolving after conversion: %v", p.dev, err)
		}
		// And the secret genuinely opens through the path the gateway uses.
		if _, err := enc.Open(res.Credential.Sealed,
			domvault.CredentialAAD(res.Credential.OrganizationID, res.Credential.ID)); err != nil {
			t.Fatalf("device %s resolved but its secret will not open: %v", p.dev, err)
		}
	}
	t.Logf("resolved and opened %d live device credentials after conversion", len(all))
}

var _ = strings.TrimSpace
