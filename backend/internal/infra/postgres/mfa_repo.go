package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// MFARepo implements iam.MFARepository. Like auth_sessions, the MFA tables are
// keyed by user (not org) and carry no RLS, so operations run system-scoped.
type MFARepo struct{ db *DB }

// NewMFARepo constructs an MFARepo.
func NewMFARepo(db *DB) *MFARepo { return &MFARepo{db: db} }

// Get returns the user's enrolled MFA method, or ErrMFANotEnrolled.
func (r *MFARepo) Get(ctx context.Context, userID iam.ID) (*iam.MFAMethod, error) {
	var out *iam.MFAMethod
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT user_id, type, secret, confirmed_at, created_at, updated_at
			FROM user_mfa WHERE user_id=$1`, userID)
		var m iam.MFAMethod
		var typ string
		if err := row.Scan(&m.UserID, &typ, &m.Secret, &m.ConfirmedAt, &m.CreatedAt, &m.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrMFANotEnrolled
			}
			return err
		}
		m.Type = iam.MFAType(typ)
		out = &m
		return nil
	})
	return out, err
}

// Upsert creates or replaces the user's (unconfirmed) MFA enrollment.
func (r *MFARepo) Upsert(ctx context.Context, m *iam.MFAMethod) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO user_mfa (user_id, type, secret, confirmed_at)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (user_id) DO UPDATE
			   SET type=EXCLUDED.type, secret=EXCLUDED.secret, confirmed_at=EXCLUDED.confirmed_at`,
			m.UserID, string(m.Type), m.Secret, m.ConfirmedAt)
		return err
	})
}

// Confirm marks an enrollment as verified.
func (r *MFARepo) Confirm(ctx context.Context, userID iam.ID, at time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE user_mfa SET confirmed_at=$2 WHERE user_id=$1`, userID, at)
		return err
	})
}

// Delete removes the enrollment and all recovery codes (via FK cascade).
func (r *MFARepo) Delete(ctx context.Context, userID iam.ID) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM user_mfa WHERE user_id=$1`, userID)
		return err
	})
}

// ReplaceRecoveryCodes discards existing codes and stores the new hashes.
func (r *MFARepo) ReplaceRecoveryCodes(ctx context.Context, userID iam.ID, hashes [][]byte) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1,$2)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// ConsumeRecoveryCode marks a matching unused code used, returning whether one
// was consumed. The UPDATE ... WHERE used_at IS NULL is atomic per row.
func (r *MFARepo) ConsumeRecoveryCode(ctx context.Context, userID iam.ID, hash []byte, at time.Time) (bool, error) {
	var consumed bool
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE user_recovery_codes SET used_at=$3
			WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`, userID, hash, at)
		if err != nil {
			return err
		}
		consumed = tag.RowsAffected() == 1
		return nil
	})
	return consumed, err
}

// CountRecoveryCodes returns the number of unused recovery codes.
func (r *MFARepo) CountRecoveryCodes(ctx context.Context, userID iam.ID) (int, error) {
	var n int
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM user_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&n)
	})
	return n, err
}
