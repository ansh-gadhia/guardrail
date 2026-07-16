package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// AuthSessionRepo implements iam.AuthSessionRepository. auth_sessions is keyed to
// a user (not an org) and has no RLS; operations run in a system-scoped tx.
type AuthSessionRepo struct{ db *DB }

// NewAuthSessionRepo constructs an AuthSessionRepo.
func NewAuthSessionRepo(db *DB) *AuthSessionRepo { return &AuthSessionRepo{db: db} }

// Create persists a refresh-token session (only the token hash is stored).
func (r *AuthSessionRepo) Create(ctx context.Context, s *iam.AuthSession) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO auth_sessions (id, user_id, family_id, refresh_token_hash,
				user_agent, ip, expires_at)
			VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,'')::inet,$7)`,
			s.ID, s.UserID, s.FamilyID, s.RefreshTokenHash, s.UserAgent, s.IP, s.ExpiresAt)
		return mapWriteErr(err)
	})
}

// GetByTokenHash looks up a session by its refresh-token hash.
func (r *AuthSessionRepo) GetByTokenHash(ctx context.Context, hash []byte) (*iam.AuthSession, error) {
	var out *iam.AuthSession
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT id, user_id, family_id, refresh_token_hash, COALESCE(host(ip),''),
				expires_at, revoked_at, created_at
			FROM auth_sessions WHERE refresh_token_hash=$1`, hash)
		var s iam.AuthSession
		if err := row.Scan(&s.ID, &s.UserID, &s.FamilyID, &s.RefreshTokenHash, &s.IP,
			&s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrRefreshInvalid
			}
			return err
		}
		out = &s
		return nil
	})
	return out, err
}

// Revoke marks a single session revoked.
func (r *AuthSessionRepo) Revoke(ctx context.Context, id iam.ID, at time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2
			WHERE id=$1 AND revoked_at IS NULL`, id, at)
		return err
	})
}

// RevokeFamily revokes every session in a token family (reuse response).
func (r *AuthSessionRepo) RevokeFamily(ctx context.Context, familyID iam.ID, at time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2
			WHERE family_id=$1 AND revoked_at IS NULL`, familyID, at)
		return err
	})
}

// RevokeAllForUser revokes all sessions for a user (e.g. on logout-all).
func (r *AuthSessionRepo) RevokeAllForUser(ctx context.Context, userID iam.ID, at time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2
			WHERE user_id=$1 AND revoked_at IS NULL`, userID, at)
		return err
	})
}

// ListActive returns one row per live login session (family). A family's live
// row is its single un-revoked, un-expired token; its created_at is the last
// activity, while the earliest created_at across the whole family is the original
// sign-in. Joined to users for the owner's email; the users read runs under the
// system scope so RLS does not hide other tenants' rows (org scoping, when asked
// for, is applied explicitly in the WHERE clause).
func (r *AuthSessionRepo) ListActive(ctx context.Context, q iam.SessionQuery) ([]iam.AuthSessionView, error) {
	var userArg, orgArg any
	if q.UserID != nil {
		userArg = *q.UserID
	}
	if q.OrgID != nil {
		orgArg = *q.OrgID
	}
	var out []iam.AuthSessionView
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT s.family_id, s.user_id, u.email, COALESCE(host(s.ip),''),
				COALESCE(s.user_agent,''), fam.first_seen, s.created_at, s.expires_at
			FROM auth_sessions s
			JOIN users u ON u.id = s.user_id
			JOIN (
				SELECT family_id, MIN(created_at) AS first_seen
				FROM auth_sessions GROUP BY family_id
			) fam ON fam.family_id = s.family_id
			WHERE s.revoked_at IS NULL
			  AND s.expires_at > now()
			  AND ($1::uuid IS NULL OR s.user_id = $1::uuid)
			  AND ($2::uuid IS NULL OR u.organization_id = $2::uuid)
			ORDER BY s.created_at DESC`, userArg, orgArg)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v iam.AuthSessionView
			if err := rows.Scan(&v.FamilyID, &v.UserID, &v.Email, &v.IP, &v.UserAgent,
				&v.SignedInAt, &v.LastSeenAt, &v.ExpiresAt); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// FamilyOwner resolves the user + organization that own a session family.
func (r *AuthSessionRepo) FamilyOwner(ctx context.Context, familyID iam.ID) (iam.ID, iam.ID, error) {
	var userID, orgID iam.ID
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT s.user_id, u.organization_id
			FROM auth_sessions s JOIN users u ON u.id = s.user_id
			WHERE s.family_id = $1 LIMIT 1`, familyID)
		if err := row.Scan(&userID, &orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrNotFound
			}
			return err
		}
		return nil
	})
	return userID, orgID, err
}
