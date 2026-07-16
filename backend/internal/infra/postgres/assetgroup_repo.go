package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// AssetGroupRepo implements assets.AssetGroupRepository.
type AssetGroupRepo struct{ db *DB }

// NewAssetGroupRepo constructs an AssetGroupRepo.
func NewAssetGroupRepo(db *DB) *AssetGroupRepo { return &AssetGroupRepo{db: db} }

// Create inserts an asset group.
func (r *AssetGroupRepo) Create(ctx context.Context, s assets.Scope, g *assets.AssetGroup) error {
	rules, _ := json.Marshal(g.MatchRules)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO asset_groups (id, organization_id, parent_id, name, type, match_rules)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			g.ID, g.OrganizationID, g.ParentID, g.Name, g.Type, rules)
		return mapWriteErr(err)
	})
}

// List returns all asset groups in scope.
func (r *AssetGroupRepo) List(ctx context.Context, s assets.Scope) ([]assets.AssetGroup, error) {
	var out []assets.AssetGroup
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, parent_id, name, type, match_rules,
			created_at, updated_at FROM asset_groups ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g assets.AssetGroup
			var rules []byte
			if err := rows.Scan(&g.ID, &g.OrganizationID, &g.ParentID, &g.Name, &g.Type,
				&rules, &g.CreatedAt, &g.UpdatedAt); err != nil {
				return err
			}
			if len(rules) > 0 {
				_ = json.Unmarshal(rules, &g.MatchRules)
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// AddMember adds a device to a group.
func (r *AssetGroupRepo) AddMember(ctx context.Context, s assets.Scope, groupID, deviceID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_group_members (device_id, asset_group_id)
			VALUES ($1,$2) ON CONFLICT DO NOTHING`, deviceID, groupID)
		return mapWriteErr(err)
	})
}

// RemoveMember removes a device from a group.
func (r *AssetGroupRepo) RemoveMember(ctx context.Context, s assets.Scope, groupID, deviceID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_group_members
			WHERE device_id=$1 AND asset_group_id=$2`, deviceID, groupID)
		return err
	})
}

// ListDeviceGroups returns the group ids a device belongs to.
func (r *AssetGroupRepo) ListDeviceGroups(ctx context.Context, s assets.Scope, deviceID uuid.UUID) ([]uuid.UUID, error) {
	out := []uuid.UUID{}
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT asset_group_id FROM device_group_members WHERE device_id=$1`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g uuid.UUID
			if err := rows.Scan(&g); err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// SetDeviceGroups replaces a device's group membership. A group id the caller's
// tenant cannot see is rejected: an FK to asset_groups would not catch that on
// its own, because foreign-key checks bypass RLS. Selecting the ids through the
// RLS-protected parent is what enforces the tenant boundary here.
func (r *AssetGroupRepo) SetDeviceGroups(ctx context.Context, s assets.Scope, deviceID uuid.UUID, groupIDs []uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_group_members WHERE device_id=$1`, deviceID); err != nil {
			return err
		}
		if len(groupIDs) == 0 {
			return nil
		}
		ct, err := tx.Exec(ctx, `
			INSERT INTO device_group_members (device_id, asset_group_id)
			SELECT $1, g.id FROM asset_groups g WHERE g.id = ANY($2::uuid[])
			ON CONFLICT DO NOTHING`, deviceID, groupIDs)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() != int64(len(groupIDs)) {
			return assets.ErrNotFound
		}
		return nil
	})
}
