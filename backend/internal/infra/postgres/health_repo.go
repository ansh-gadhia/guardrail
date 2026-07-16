package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// HealthRepo implements assets.HealthRepository. Every method runs under the
// system scope: the poller is a background loop with no acting user, and it must
// see and update devices across all tenants.
type HealthRepo struct{ db *DB }

// NewHealthRepo constructs a HealthRepo.
func NewHealthRepo(db *DB) *HealthRepo { return &HealthRepo{db: db} }

// ListProbeTargets returns every active device in every organization, along with
// its current failure streak.
func (r *HealthRepo) ListProbeTargets(ctx context.Context) ([]assets.ProbeTarget, error) {
	out := []assets.ProbeTarget{}
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id, d.host, d.port, d.scheme, d.verify_tls,
				COALESCE(h.consecutive_failures, 0)
			FROM devices d
			LEFT JOIN device_health h ON h.device_id = d.id
			WHERE d.status = 'active' AND d.deleted_at IS NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t assets.ProbeTarget
			if err := rows.Scan(&t.DeviceID, &t.Host, &t.Port, &t.Scheme, &t.VerifyTLS, &t.ConsecutiveFailures); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// Upsert records one probe result.
func (r *HealthRepo) Upsert(ctx context.Context, deviceID uuid.UUID, h assets.Health) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO device_health (device_id, status, checked_at, latency_ms, consecutive_failures, last_error)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (device_id) DO UPDATE SET
				status = EXCLUDED.status,
				checked_at = EXCLUDED.checked_at,
				latency_ms = EXCLUDED.latency_ms,
				consecutive_failures = EXCLUDED.consecutive_failures,
				last_error = EXCLUDED.last_error`,
			deviceID, string(h.Status), h.CheckedAt, h.LatencyMS, h.ConsecutiveFailures, nullIfEmpty(h.LastError))
		return err
	})
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
