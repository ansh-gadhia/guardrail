//go:build integration

package test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/config"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/platform/database"
)

// Teardown for the integration suite.
//
// These tests run against a REAL database, and on a developer box that is
// usually a working deployment — the same one the console is pointed at. Rows
// they leave behind are not invisible test detritus: they turn up in somebody's
// device inventory, their dashboard counts, and the SIEM's status feed. A single
// `make test-integration` used to add well over a hundred devices and as many
// users, and nothing ever took them out again.
//
// Tracking is EXPLICIT — every row a test creates is recorded by id — rather
// than snapshot-and-delete-whatever-appeared. The suite shares an organization
// with the live deployment, so "delete rows that showed up while the test ran"
// would eventually delete a device somebody registered from the console in the
// same minute. Recording ids cannot do that, at the cost of a track call at each
// creation site.
//
// The tracker deliberately does NOT reuse the test's own connection pool. An
// earlier version hung the teardown off the pool that newPG hands out, which
// meant two things silently: a test that never called newPG tracked into nothing
// at all, and the ordering between `defer closeDB()` and t.Cleanup decided
// whether the pool was still open when the purge ran. Opening a short-lived
// connection of its own removes both couplings — the teardown works for any test
// that creates a row, however it got its database handle.

var currentResidue *residue

type residue struct {
	t           *testing.T
	devices     []uuid.UUID
	users       []uuid.UUID
	groups      []uuid.UUID
	teams       []uuid.UUID
	credentials []uuid.UUID
}

// residueFor returns the tracker for the running test, registering its teardown
// the first time the test records anything. Tests are serial (nothing calls
// t.Parallel), which is what makes one package-level current tracker safe; if
// that ever changes this has to be threaded through the fixtures instead.
func residueFor(t *testing.T) *residue {
	if currentResidue != nil && currentResidue.t == t {
		return currentResidue
	}
	r := &residue{t: t}
	currentResidue = r
	t.Cleanup(func() {
		r.purge(t)
		if currentResidue == r {
			currentResidue = nil
		}
	})
	return r
}

// The track helpers return their argument so a creation site can wrap an id
// inline: `return trackUser(t, t, u.ID)`.

func trackDevice(t *testing.T, id uuid.UUID) uuid.UUID {
	r := residueFor(t)
	r.devices = append(r.devices, id)
	return id
}

func trackUser(t *testing.T, id domiam.ID) domiam.ID {
	r := residueFor(t)
	r.users = append(r.users, uuid.UUID(id))
	return id
}

func trackGroup(t *testing.T, id uuid.UUID) uuid.UUID {
	r := residueFor(t)
	r.groups = append(r.groups, id)
	return id
}

func trackTeam(t *testing.T, id domiam.ID) domiam.ID {
	r := residueFor(t)
	r.teams = append(r.teams, uuid.UUID(id))
	return id
}

func trackCredential(t *testing.T, id uuid.UUID) uuid.UUID {
	r := residueFor(t)
	r.credentials = append(r.credentials, id)
	return id
}

// purge removes every tracked row, in dependency order.
//
// access_sessions references devices and users with ON DELETE RESTRICT, so the
// sessions go before the rows they point at. api_tokens references users with
// ON DELETE SET NULL, which would leave the token behind holding a null author,
// so those are deleted explicitly rather than left to the constraint.
// credentials come after devices and groups because device_credentials and
// group_credentials reference them with RESTRICT and cascade from their own
// parent.
//
// audit_events is deliberately untouched. It is an append-only hash chain, and
// deleting rows from it forks the chain and breaks POST /audit/verify
// permanently. Events naming a device that no longer exists are correct: that is
// what a historical record looks like.
//
// Failures are reported, not fatal — a teardown that calls t.Fatal replaces the
// real failure of the test it is tearing down with its own.
func (r *residue) purge(t *testing.T) {
	t.Helper()
	if len(r.devices)+len(r.users)+len(r.groups)+len(r.teams)+len(r.credentials) == 0 {
		return
	}
	dsn := os.Getenv("GUARDRAIL_TEST_DSN")
	if dsn == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.New(ctx, config.PostgresConfig{
		DSN: dsn, MaxConns: 2, MinConns: 1, MaxConnLifetime: time.Minute,
	})
	if err != nil {
		t.Errorf("integration teardown could not connect, rows left behind: %v", err)
		return
	}
	defer db.Close()

	err = postgres.New(db.Pool).WithSystemScope(ctx, func(tx pgx.Tx) error {
		d, u := r.devices, r.users
		for _, q := range []string{
			`DELETE FROM access_request_decisions WHERE request_id IN (
			   SELECT id FROM access_requests WHERE device_id = ANY($1) OR user_id = ANY($2))`,
			`DELETE FROM device_access_grants WHERE device_id = ANY($1) OR user_id = ANY($2)`,
			`DELETE FROM access_requests      WHERE device_id = ANY($1) OR user_id = ANY($2)`,
			`DELETE FROM access_sessions      WHERE device_id = ANY($1) OR user_id = ANY($2)`,
		} {
			if _, err := tx.Exec(ctx, q, d, u); err != nil {
				return err
			}
		}
		// api_tokens.created_by is ON DELETE SET NULL, so deleting the user would
		// leave the token behind with a null author rather than removing it.
		if _, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE created_by = ANY($1)`, u); err != nil {
			return err
		}
		// Credentials minted by a SERVICE rather than by the test. When a test
		// calls something like vault.SetForUser, the credential row is created
		// inside the call and its id never comes back, so nothing can track it.
		// Deleting the device only cascades the BINDING; the credential itself
		// survives as an orphan.
		//
		// So find them by reachability instead, while the bindings still exist.
		// The two NOT EXISTS clauses are what keep this honest: a credential is
		// collected only if EVERY binding it has is to a device or group this
		// test created. One shared with anything outside that set is left alone.
		orphans := []uuid.UUID{}
		rows, err := tx.Query(ctx, `
			WITH bound AS (
			    SELECT credential_id AS id FROM device_credentials WHERE device_id = ANY($1)
			    UNION
			    SELECT credential_id      FROM group_credentials  WHERE asset_group_id = ANY($2)
			)
			SELECT b.id FROM bound b
			WHERE NOT EXISTS (SELECT 1 FROM device_credentials dc
			                  WHERE dc.credential_id = b.id AND NOT (dc.device_id = ANY($1)))
			  AND NOT EXISTS (SELECT 1 FROM group_credentials gc
			                  WHERE gc.credential_id = b.id AND NOT (gc.asset_group_id = ANY($2)))`,
			d, r.groups)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			orphans = append(orphans, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// device_credentials.credential_id is ON DELETE RESTRICT, so the bindings
		// have to go before the credential rows they point at — the cascade from
		// the device is not enough, because it has not happened yet.
		for _, q := range []struct {
			sql string
			ids []uuid.UUID
		}{
			{`DELETE FROM device_credentials WHERE device_id = ANY($1)`, d},
			{`DELETE FROM group_credentials  WHERE asset_group_id = ANY($1)`, r.groups},
		} {
			if len(q.ids) == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, q.sql, q.ids); err != nil {
				return err
			}
		}
		creds := append(append([]uuid.UUID{}, r.credentials...), orphans...)

		for _, q := range []struct {
			sql string
			ids []uuid.UUID
		}{
			{`DELETE FROM devices      WHERE id = ANY($1)`, r.devices},
			{`DELETE FROM teams        WHERE id = ANY($1)`, r.teams},
			{`DELETE FROM asset_groups WHERE id = ANY($1)`, r.groups},
			{`DELETE FROM credentials  WHERE id = ANY($1)`, creds},
			{`DELETE FROM users        WHERE id = ANY($1)`, r.users},
		} {
			if len(q.ids) == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, q.sql, q.ids); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("integration teardown left rows in the database: %v", err)
	}
}
