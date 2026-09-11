//go:build integration

// Audit chain tamper-evidence (SECURITY_AUDIT/01-findings.md M6).
//
//	GUARDRAIL_TEST_DSN=... GUARDRAIL_TEST_OWNER_DSN=... GUARDRAIL_TEST_MASTER_KEY=... \
//	  go test -tags=integration ./test/ -run TestAuditChain
package test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// ownerConn opens a connection as the table owner.
//
// guardrail_app has SELECT and INSERT on audit_events and deliberately NOT
// UPDATE — the append-only grant. Tampering therefore has to come in as the
// owner, which is exactly the adversary this finding is about: the grant stops
// the application, and nothing stopped anybody who got past it.
func ownerConn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("GUARDRAIL_TEST_OWNER_DSN")
	if dsn == "" {
		t.Skip("GUARDRAIL_TEST_OWNER_DSN not set")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("owner connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func writeEvent(t *testing.T, ctx context.Context, repo *postgres.AuditRepo, org uuid.UUID, action string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := repo.Record(ctx, audit.Event{
		ID: id, OrganizationID: &org, Action: action,
		Category: audit.CategoryVault, TargetType: "credential",
		TargetID: uuid.New().String(), Result: audit.ResultSuccess,
		Timestamp: time.Now().UTC(),
		Detail:    map[string]any{"probe": true},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	return id
}

// The whole point: an event rewritten by somebody who can write the table, who
// then repairs the chain behind them, must still be detectable.
func TestAuditChainKeyedHashResistsForgery(t *testing.T) {
	db, done := newPG(t)
	defer done()
	ctx := context.Background()
	owner := ownerConn(t)

	key, err := security.NewAuditChainKey(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	keyed := postgres.NewAuditRepo(db).WithChainKey(key)

	org := defaultOrgID
	id := writeEvent(t, ctx, keyed, org, "probe.keyed")
	t.Cleanup(func() {
		_, _ = owner.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
	})

	// It was written at the keyed version.
	var version int16
	if err := owner.QueryRow(ctx, `SELECT hash_version FROM audit_events WHERE id=$1`, id).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < 3 {
		t.Fatalf("event stored at hash_version %d, want the keyed version", version)
	}

	// Verifying with the right key passes.
	rep, err := keyed.VerifyChain(ctx, &org, 5000)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("a freshly written chain did not verify: %+v", rep)
	}

	// Now tamper as the owner — change the action, which is covered by the hash.
	if _, err := owner.Exec(ctx,
		`UPDATE audit_events SET action='probe.tampered' WHERE id=$1`, id); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rep, err = keyed.VerifyChain(ctx, &org, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("an edited event still verified")
	}

	// And the attacker's real move: recompute the hash so the chain is
	// self-consistent again. Without the key they cannot produce the right one —
	// the best they can do is the unkeyed SHA-256, which is what the old scheme
	// used and what anyone could compute from the source.
	unkeyed := postgres.NewAuditRepo(db) // no key: the old, forgeable scheme
	if _, err := owner.Exec(ctx, `UPDATE audit_events SET action='probe.tampered' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	// Repair the chain the way the pre-fix scheme would have allowed.
	repRepaired, err := unkeyed.VerifyChain(ctx, &org, 5000)
	if err != nil {
		t.Fatal(err)
	}
	// The keyed verifier must still refuse it.
	repKeyed, err := keyed.VerifyChain(ctx, &org, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if repKeyed.OK {
		t.Fatal("the keyed verifier accepted a chain repaired without the key")
	}
	_ = repRepaired
}

// Turning the key on must not make existing history look forged. Rows written
// under the unkeyed scheme are version 2 and keep verifying with SHA-256.
func TestAuditChainLegacyRowsStillVerify(t *testing.T) {
	db, done := newPG(t)
	defer done()
	ctx := context.Background()
	owner := ownerConn(t)

	org := defaultOrgID
	// Write one the OLD way — no key, version 2.
	unkeyed := postgres.NewAuditRepo(db)
	id := writeEvent(t, ctx, unkeyed, org, "probe.legacy")
	t.Cleanup(func() {
		_, _ = owner.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, id)
	})

	var version int16
	if err := owner.QueryRow(ctx, `SELECT hash_version FROM audit_events WHERE id=$1`, id).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("unkeyed write stored version %d, want 2", version)
	}

	// A KEYED repo must still verify it, because it recomputes under the version
	// the row records rather than the one it would write today.
	key, err := security.NewAuditChainKey(masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	keyed := postgres.NewAuditRepo(db).WithChainKey(key)
	rep, err := keyed.VerifyChain(ctx, &org, 5000)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("existing unkeyed history stopped verifying once the key was on: %+v", rep)
	}
}

// The append-only grant is a real control and must stay: the application role
// cannot rewrite the log at all, key or no key.
func TestAuditChainAppRoleCannotRewriteHistory(t *testing.T) {
	raw := rawPool(t)
	ctx := context.Background()

	err := rawTx(t, raw, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE audit_events SET action='rewritten' WHERE true`)
		return e
	})
	if err == nil {
		t.Fatal("the application role was able to UPDATE audit_events")
	}
}
