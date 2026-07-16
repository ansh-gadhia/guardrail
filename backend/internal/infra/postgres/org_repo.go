package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// OrgRepo implements iam.OrganizationRepository.
type OrgRepo struct{ db *DB }

// NewOrgRepo constructs an OrgRepo.
func NewOrgRepo(db *DB) *OrgRepo { return &OrgRepo{db: db} }

const orgColumns = `id, name, slug, status, created_at, updated_at`

func scanOrg(row pgx.Row) (*iam.Organization, error) {
	var o iam.Organization
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	return &o, nil
}

// Create inserts an organization (super-admin scope required by RLS).
func (r *OrgRepo) Create(ctx context.Context, s iam.TenantScope, o *iam.Organization) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, slug, status)
			VALUES ($1,$2,$3,$4)`, o.ID, o.Name, o.Slug, o.Status)
		return mapWriteErr(err)
	})
}

// Update mutates organization fields.
func (r *OrgRepo) Update(ctx context.Context, s iam.TenantScope, o *iam.Organization) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE organizations SET name=$2, status=$3, updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, o.ID, o.Name, o.Status)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// GetByID loads an organization within scope.
func (r *OrgRepo) GetByID(ctx context.Context, s iam.TenantScope, id iam.ID) (*iam.Organization, error) {
	var o *iam.Organization
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+orgColumns+`
			FROM organizations WHERE id=$1 AND deleted_at IS NULL`, id)
		var e error
		o, e = scanOrg(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		return e
	})
	return o, err
}

// GetBySlug resolves an organization by slug (pre-auth, RLS bypassed).
func (r *OrgRepo) GetBySlug(ctx context.Context, slug string) (*iam.Organization, error) {
	var o *iam.Organization
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+orgColumns+`
			FROM organizations WHERE slug=$1 AND deleted_at IS NULL`, slug)
		var e error
		o, e = scanOrg(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		return e
	})
	return o, err
}

// List returns organizations visible to the scope.
func (r *OrgRepo) List(ctx context.Context, s iam.TenantScope, page iam.Page) ([]iam.Organization, error) {
	limit := normalizeLimit(page.Limit)
	var out []iam.Organization
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+orgColumns+`
			FROM organizations WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, e := scanOrg(rows)
			if e != nil {
				return e
			}
			out = append(out, *o)
		}
		return rows.Err()
	})
	return out, err
}
