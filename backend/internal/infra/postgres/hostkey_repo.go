package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// HostKeyRepo pins SSH host keys per device (trust-on-first-use).
type HostKeyRepo struct{ db *DB }

// NewHostKeyRepo constructs a HostKeyRepo.
func NewHostKeyRepo(db *DB) *HostKeyRepo { return &HostKeyRepo{db: db} }

// Get returns the pinned key for a device, or "" when none is pinned.
//
// System scope: the pin is a fact about a machine, and it is consulted during a
// handshake that has already been authorized by the broker. Reading it under the
// caller's tenant scope would add nothing — the device_id came from a device the
// caller was allowed to reach — while making a host-key check depend on RLS
// state, where a miss silently means "never seen before" and trusts a new key.
func (r *HostKeyRepo) Get(ctx context.Context, deviceID string) (string, error) {
	var key string
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT host_key FROM device_host_keys WHERE device_id=$1`, deviceID).Scan(&key)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil // not pinned yet; "" is the honest answer
		}
		return e
	})
	return key, err
}

// Pin records the key seen on first contact.
//
// ON CONFLICT DO NOTHING, not DO UPDATE: two concurrent first connections must
// agree on one key, and an UPDATE here would make Pin silently overwrite a pin —
// turning the one control that detects a substituted host into a no-op.
func (r *HostKeyRepo) Pin(ctx context.Context, deviceID, key string) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO device_host_keys (device_id, host_key) VALUES ($1,$2)
			ON CONFLICT (device_id) DO NOTHING`, deviceID, key)
		return err
	})
}

// Clear removes a device's pin, so the next connection re-pins.
//
// This is the escape hatch for a legitimately rebuilt host. It is deliberately
// an explicit admin action: the alternative — trusting a changed key
// automatically — is indistinguishable from accepting an interception.
func (r *HostKeyRepo) Clear(ctx context.Context, deviceID string) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_host_keys WHERE device_id=$1`, deviceID)
		return err
	})
}
