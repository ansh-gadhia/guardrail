//go:build integration

// Binding integrity (SECURITY_AUDIT/01-findings.md C1, second half).
//
//	GUARDRAIL_TEST_DSN=postgres://guardrail_app:...@127.0.0.1:5432/guardrail?sslmode=disable \
//	  go test -tags=integration ./test/ -run TestBinding
package test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// rawPool opens a second connection for the direct SQL these tests need. The
// repo exposes no way to reach past itself, which is right — so the tampering
// half of this has to come in through the side.
func rawPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("GUARDRAIL_TEST_DSN")
	if dsn == "" {
		t.Skip("GUARDRAIL_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// rawTx runs fn with row-level security bypassed for the life of one
// transaction.
//
// SET LOCAL inside a transaction, not a session SET: pgxpool issues DISCARD ALL
// when a connection returns to the pool, so a session-level setting is gone by
// the next query. That presented as "no rows in result set" and silently
// SKIPPED this test rather than failing it — a false pass, which is worse than
// a red build.
func rawTx(t *testing.T, raw *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := raw.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL app.is_super_admin = 'on'"); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// The property that matters most: turning this on must not stop an existing
// device session from resolving. Every binding written before migration 0035
// has a NULL signature, and a security upgrade that takes the estate offline
// gets rolled back rather than kept.
func TestBindingUnsignedRowsStillResolve(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	// The DEPLOYMENT's key, not a fixture one. These tests write signatures into
	// a shared database; signing with anything else would leave every binding
	// unverifiable by the real API — a test that breaks the thing it checks.
	signer, err := security.NewBindingSigner(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewCredentialRepo(db).WithBindingSigner(signer)

	// Rows of our own, so this exercises something on a clean database instead
	// of skipping. On a populated one it simply joins the estate below.
	seedBinding(t, db)

	// Reproduce a pre-0035 database.
	var unsigned int
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE device_credentials SET binding_mac = NULL`); e != nil {
			return e
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM device_credentials WHERE binding_mac IS NULL`).Scan(&unsigned)
	}); err != nil {
		t.Fatalf("could not clear signatures: %v", err)
	}
	if unsigned == 0 {
		t.Skip("no bindings in this database to exercise")
	}

	// Unsigned rows must still resolve, or live sessions break.
	if err := resolveEveryBinding(t, raw, repo); err != nil {
		t.Fatalf("an unsigned binding stopped resolving, which would break live sessions: %v", err)
	}

	n, err := repo.SignUnsignedBindings(ctx)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != unsigned {
		t.Errorf("backfill signed %d rows, %d were unsigned", n, unsigned)
	}

	// Idempotent: a second boot finds nothing.
	if again, e := repo.SignUnsignedBindings(ctx); e != nil || again != 0 {
		t.Errorf("second backfill signed %d rows (err %v), want 0", again, e)
	}

	if err := resolveEveryBinding(t, raw, repo); err != nil {
		t.Fatalf("a signed binding stopped resolving: %v", err)
	}
}

// The attack: repoint a binding at a credential you may not have, by hand.
func TestBindingRepointIsRefused(t *testing.T) {
	db, done := newPG(t)
	defer done()
	raw := rawPool(t)
	ctx := context.Background()

	signer, err := security.NewBindingSigner(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewCredentialRepo(db).WithBindingSigner(signer)
	if _, err := repo.SignUnsignedBindings(ctx); err != nil {
		t.Fatal(err)
	}

	// Its own device and its own two credentials, rather than whichever live row
	// the database happened to return first. Deterministic, present on a clean
	// database, and — since the tamper below rewrites a binding — it is a
	// fixture that gets repointed rather than something the estate depends on.
	seeded := seedBinding(t, db)
	devID, credID, orgID, otherCred := seeded.device, seeded.cred, seeded.org, seeded.otherCred
	if _, err := repo.SignUnsignedBindings(ctx); err != nil {
		t.Fatalf("sign the seeded binding: %v", err)
	}

	scope := domvault.Scope{OrganizationID: orgID}
	if _, err := repo.ResolveForDevice(ctx, scope, devID, uuid.Nil); err != nil {
		t.Fatalf("baseline resolve failed before tampering: %v", err)
	}

	// Tamper exactly as an attacker with row-write would: keep the signature,
	// point the row at a credential they are not entitled to.
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE device_credentials SET credential_id=$2 WHERE device_id=$1 AND credential_id=$3`,
			devID, otherCred, credID)
		return e
	}); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	defer func() {
		_ = rawTx(t, raw, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx,
				`UPDATE device_credentials SET credential_id=$3 WHERE device_id=$1 AND credential_id=$2`,
				devID, otherCred, credID)
			return e
		})
	}()

	_, err = repo.ResolveForDevice(ctx, scope, devID, uuid.Nil)
	if err == nil {
		t.Fatal("a repointed binding resolved: the gateway would have injected the wrong credential")
	}
	if !strings.Contains(err.Error(), "not signed") {
		t.Errorf("refused, but not as a signature failure: %v", err)
	}
}

// resolveEveryBinding walks every shared binding and resolves it, so a
// regression reads as "this device stopped working" rather than a count.
func resolveEveryBinding(t *testing.T, raw *pgxpool.Pool, repo *postgres.CredentialRepo) error {
	t.Helper()
	ctx := context.Background()
	type pair struct{ dev, org uuid.UUID }
	var all []pair
	if err := rawTx(t, raw, func(tx pgx.Tx) error {
		// Live devices only. A soft-deleted device keeps its binding row (see
		// finding M9) and ResolveForDevice correctly refuses it, so including
		// them here would report the product working as intended as a failure.
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
		return err
	}
	for _, p := range all {
		if _, err := repo.ResolveForDevice(ctx, domvault.Scope{OrganizationID: p.org}, p.dev, uuid.Nil); err != nil {
			return err
		}
	}
	return nil
}
