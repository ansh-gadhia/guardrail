// Package postgres implements the IAM and audit repository ports on PostgreSQL
// using pgx. Every tenant-scoped operation runs inside a transaction that sets
// the RLS GUCs (app.current_org / app.is_super_admin), so Row-Level Security is
// the enforced second layer of tenant isolation behind the application scope.
package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// DB is the shared handle for all repositories.
type DB struct {
	pool *pgxpool.Pool
}

// New wraps a pgx pool.
func New(pool *pgxpool.Pool) *DB { return &DB{pool: pool} }

// withScope runs fn inside a transaction with the tenant GUCs set for RLS. The
// GUCs are LOCAL, so they are scoped to (and cleared at the end of) this tx.
func (db *DB) withScope(ctx context.Context, s iam.TenantScope, fn func(tx pgx.Tx) error) error {
	return db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, fn)
}

// WithScopeIDs runs fn inside a tenant-scoped transaction, keyed by raw ids so
// the assets and vault repositories can reuse the RLS plumbing without importing
// the IAM types.
func (db *DB) WithScopeIDs(ctx context.Context, orgID uuid.UUID, isSuper bool, fn func(tx pgx.Tx) error) error {
	org := ""
	if orgID != (uuid.UUID{}) {
		org = orgID.String()
	}
	sadmin := "off"
	if isSuper {
		sadmin = "on"
	}
	return db.inTx(ctx, org, sadmin, fn)
}

// WithSystemScope exposes the trusted, RLS-bypassing scope for cross-tenant jobs
// (e.g. KEK rotation) that operate outside a single tenant.
func (db *DB) WithSystemScope(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return db.withSystemScope(ctx, fn)
}

// withSystemScope runs fn as a trusted system operation (RLS bypassed). It is
// used only for pre-authentication lookups where no tenant is established yet
// (resolving a user by email, an org by slug) and for refresh-token bookkeeping.
func (db *DB) withSystemScope(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return db.inTx(ctx, "", "on", fn)
}

func (db *DB) inTx(ctx context.Context, org, sadmin string, fn func(tx pgx.Tx) error) (err error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err = tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", org); err != nil {
		return fmt.Errorf("postgres: set current_org: %w", err)
	}
	if _, err = tx.Exec(ctx, "SELECT set_config('app.is_super_admin', $1, true)", sadmin); err != nil {
		return fmt.Errorf("postgres: set is_super_admin: %w", err)
	}

	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}
