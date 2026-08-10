package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// APITokenRepo implements iam.APITokenRepository.
type APITokenRepo struct{ db *DB }

// NewAPITokenRepo constructs an APITokenRepo.
func NewAPITokenRepo(db *DB) *APITokenRepo { return &APITokenRepo{db: db} }

const apiTokenCols = `id, organization_id, name, token_hash, prefix, scopes,
	created_by, expires_at, last_used_at, revoked_at, created_at`

func scanAPIToken(row pgx.Row) (*iam.APIToken, error) {
	var t iam.APIToken
	if err := row.Scan(&t.ID, &t.OrganizationID, &t.Name, &t.Hash, &t.Prefix, &t.Scopes,
		&t.CreatedBy, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// Create stores a new token.
func (r *APITokenRepo) Create(ctx context.Context, s iam.TenantScope, t *iam.APIToken) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO api_tokens (id, organization_id, name, token_hash, prefix, scopes,
				created_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			t.ID, t.OrganizationID, t.Name, t.Hash, t.Prefix, t.Scopes, t.CreatedBy, t.ExpiresAt)
		return mapWriteErr(err)
	})
}

// List returns the organization's tokens, newest first. The hash is selected but
// is never rendered by the delivery layer — it is not a secret that can be
// reversed, but it is also of no use to anyone but the verifier.
func (r *APITokenRepo) List(ctx context.Context, s iam.TenantScope) ([]iam.APIToken, error) {
	var out []iam.APIToken
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+apiTokenCols+` FROM api_tokens ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, e := scanAPIToken(rows)
			if e != nil {
				return e
			}
			out = append(out, *t)
		}
		return rows.Err()
	})
	return out, err
}

// Revoke marks a token unusable. It is a soft revoke on purpose: the row is what
// tells a reviewer this credential existed, who issued it, and when it stopped
// working. Deleting it would erase the answer along with the access.
func (r *APITokenRepo) Revoke(ctx context.Context, s iam.TenantScope, id iam.ID, at time.Time) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, at)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// FindByHash resolves a presented token.
//
// Deliberately unscoped: this call is what DECIDES the tenant, so there is no
// organization to scope it to yet. It runs as the app role with RLS bypassed for
// this statement only, and the lookup is by a 256-bit hash — an attacker who
// could reach it would already need the token.
func (r *APITokenRepo) FindByHash(ctx context.Context, hash []byte) (*iam.APIToken, error) {
	var t *iam.APIToken
	err := r.db.withScope(ctx, iam.TenantScope{IsSuperAdmin: true}, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash=$1`, hash)
		var e error
		t, e = scanAPIToken(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		return e
	})
	return t, err
}

// TouchUsed stamps last use.
func (r *APITokenRepo) TouchUsed(ctx context.Context, id iam.ID, at time.Time) error {
	return r.db.withScope(ctx, iam.TenantScope{IsSuperAdmin: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_tokens SET last_used_at=$2 WHERE id=$1`, id, at)
		return err
	})
}
