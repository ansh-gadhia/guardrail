package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// SettingsRepo reads and writes per-organization policy settings.
type SettingsRepo struct {
	db *DB
	// seedRetention is the value a tenant that has never set one inherits: what
	// the deployment's environment asked for. It is only ever used to CREATE the
	// row, never to override one — otherwise a restart would silently undo every
	// change an administrator made in the console.
	seedRetention time.Duration
}

// NewSettingsRepo constructs a SettingsRepo. seedRetention comes from
// configuration (GUARDRAIL_RECORDING_RETENTION_DAYS) and seeds tenants that have
// no row yet.
func NewSettingsRepo(db *DB, seedRetention time.Duration) *SettingsRepo {
	return &SettingsRepo{db: db, seedRetention: seedRetention}
}

// GetSettings returns an organization's settings, creating the row from the
// deployment's configured defaults the first time it is asked for.
func (r *SettingsRepo) GetSettings(ctx context.Context, s access.Scope, orgID uuid.UUID) (*access.OrgSettings, error) {
	var out access.OrgSettings
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		if err := r.load(ctx, tx, orgID, &out); err != nil {
			return err
		}
		if out.UpdatedBy != nil {
			// Best-effort: the row survives the user who set it, and a deleted
			// administrator must not blank the whole panel.
			_ = tx.QueryRow(ctx, `SELECT COALESCE(email::text,'') FROM users WHERE id=$1`, *out.UpdatedBy).
				Scan(&out.UpdatedByEmail)
		}
		return nil
	})
	out.ConfiguredDefaultDays = r.seedDays()
	return &out, err
}

func (r *SettingsRepo) seedDays() int {
	d := int(r.seedRetention.Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func (r *SettingsRepo) load(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, out *access.OrgSettings) error {
	// ON CONFLICT DO NOTHING then read: two requests arriving together must not
	// race into a duplicate-key error on a row neither of them cares about
	// creating.
	seed := r.seedDays()
	if _, err := tx.Exec(ctx, `
		INSERT INTO org_settings (organization_id, recording_retention_days)
		VALUES ($1, $2) ON CONFLICT (organization_id) DO NOTHING`, orgID, seed); err != nil {
		return fmt.Errorf("settings: seed: %w", err)
	}
	var allow, block []byte
	if err := tx.QueryRow(ctx, `
		SELECT recording_retention_days, updated_at, updated_by,
		       client_name, client_logo, branding_enabled,
		       ip_allowlist_enabled, ip_allowlist, ip_blocklist_enabled, ip_blocklist
		  FROM org_settings WHERE organization_id=$1`, orgID).
		Scan(&out.RecordingRetentionDays, &out.UpdatedAt, &out.UpdatedBy,
			&out.Branding.ClientName, &out.Branding.ClientLogo, &out.Branding.Enabled,
			&out.Network.AllowEnabled, &allow, &out.Network.BlockEnabled, &block); err != nil {
		return fmt.Errorf("settings: read: %w", err)
	}
	out.Network.Allow = decodeRules(allow)
	out.Network.Block = decodeRules(block)
	return nil
}

// decodeRules is deliberately forgiving: a malformed list must not make the
// settings page unreadable, and an empty list is the safe reading of one we
// cannot parse — it disables nothing that was working and locks nobody out.
func decodeRules(raw []byte) []access.NetworkRule {
	if len(raw) == 0 {
		return nil
	}
	var out []access.NetworkRule
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// SetBranding stores how this organization's console presents itself.
func (r *SettingsRepo) SetBranding(ctx context.Context, s access.Scope, orgID uuid.UUID, b access.Branding, by uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		var cur access.OrgSettings
		if err := r.load(ctx, tx, orgID, &cur); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			UPDATE org_settings
			   SET client_name=$2, client_logo=$3, branding_enabled=$4,
			       updated_at=now(), updated_by=$5
			 WHERE organization_id=$1`, orgID, b.ClientName, b.ClientLogo, b.Enabled, by)
		if err != nil {
			return fmt.Errorf("settings: update branding: %w", err)
		}
		return nil
	})
}

// SetNetworkPolicy stores which source addresses may reach the console.
func (r *SettingsRepo) SetNetworkPolicy(ctx context.Context, s access.Scope, orgID uuid.UUID, p access.NetworkPolicy, by uuid.UUID) error {
	allow, err := json.Marshal(nonNil(p.Allow))
	if err != nil {
		return fmt.Errorf("settings: encode allowlist: %w", err)
	}
	block, err := json.Marshal(nonNil(p.Block))
	if err != nil {
		return fmt.Errorf("settings: encode blocklist: %w", err)
	}
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		var cur access.OrgSettings
		if err := r.load(ctx, tx, orgID, &cur); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings
			   SET ip_allowlist_enabled=$2, ip_allowlist=$3,
			       ip_blocklist_enabled=$4, ip_blocklist=$5,
			       updated_at=now(), updated_by=$6
			 WHERE organization_id=$1`,
			orgID, p.AllowEnabled, allow, p.BlockEnabled, block, by); err != nil {
			return fmt.Errorf("settings: update network policy: %w", err)
		}
		return nil
	})
}

// nonNil keeps a nil slice out of the JSON: the column is CHECKed as an array,
// and `null` is not one.
func nonNil(rules []access.NetworkRule) []access.NetworkRule {
	if rules == nil {
		return []access.NetworkRule{}
	}
	return rules
}

// NetworkPolicyFor reads the policy with no acting user, for the middleware that
// runs on every authenticated request.
func (r *SettingsRepo) NetworkPolicyFor(ctx context.Context, orgID uuid.UUID) (access.NetworkPolicy, error) {
	var out access.OrgSettings
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		return r.load(ctx, tx, orgID, &out)
	})
	return out.Network, err
}

// SetRecordingRetention stores a new retention policy, in days. Zero keeps
// recordings indefinitely.
func (r *SettingsRepo) SetRecordingRetention(ctx context.Context, s access.Scope, orgID uuid.UUID, days int, by uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		var cur access.OrgSettings
		if err := r.load(ctx, tx, orgID, &cur); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE org_settings
			   SET recording_retention_days=$2, updated_at=now(), updated_by=$3
			 WHERE organization_id=$1`, orgID, days, by); err != nil {
			return fmt.Errorf("settings: update retention: %w", err)
		}
		// Existing recordings move with the policy. The alternative — a new
		// deadline that applies only to future sessions — means shortening
		// retention leaves the old evidence sitting there anyway, which is the
		// opposite of what somebody shortening it is asking for. Lengthening it
		// works the same way round, and cannot resurrect what has already gone.
		if days > 0 {
			_, err := tx.Exec(ctx, `
				UPDATE recordings SET retention_until = started_at + make_interval(days => $2)
				 WHERE organization_id=$1`, orgID, days)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE recordings SET retention_until = NULL WHERE organization_id=$1`, orgID)
		return err
	})
}

// RecordingRetention implements access.SettingsStore for the broker, which needs
// the policy with no acting user: at connect, to stamp a new recording's
// deadline, and in the purge sweep.
func (r *SettingsRepo) RecordingRetention(ctx context.Context, orgID uuid.UUID) (time.Duration, error) {
	var days int
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		var out access.OrgSettings
		if err := r.load(ctx, tx, orgID, &out); err != nil {
			return err
		}
		days = out.RecordingRetentionDays
		return nil
	})
	return time.Duration(days) * 24 * time.Hour, err
}
