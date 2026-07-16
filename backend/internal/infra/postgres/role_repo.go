package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// RoleRepo implements iam.RoleRepository.
type RoleRepo struct{ db *DB }

// NewRoleRepo constructs a RoleRepo.
func NewRoleRepo(db *DB) *RoleRepo { return &RoleRepo{db: db} }

// List returns roles visible to the scope (org roles + system templates) with
// their permission keys.
func (r *RoleRepo) List(ctx context.Context, s iam.TenantScope, page iam.Page) ([]iam.Role, error) {
	limit := normalizeLimit(page.Limit)
	var out []iam.Role
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT r.id, r.organization_id, r.name, r.description, r.is_system, r.device_scope,
				COALESCE(array_agg(p.key) FILTER (WHERE p.key IS NOT NULL), '{}') AS perms
			FROM roles r
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id
			GROUP BY r.id
			ORDER BY r.is_system DESC, r.name
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			role, e := scanRole(rows)
			if e != nil {
				return e
			}
			out = append(out, *role)
		}
		return rows.Err()
	})
	return out, err
}

// GetByID loads one role with permissions.
func (r *RoleRepo) GetByID(ctx context.Context, s iam.TenantScope, id iam.ID) (*iam.Role, error) {
	var role *iam.Role
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT r.id, r.organization_id, r.name, r.description, r.is_system, r.device_scope,
				COALESCE(array_agg(p.key) FILTER (WHERE p.key IS NOT NULL), '{}') AS perms
			FROM roles r
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id
			WHERE r.id=$1
			GROUP BY r.id`, id)
		var e error
		role, e = scanRole(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		return e
	})
	return role, err
}

// Create inserts a custom (non-system) role in the tenant.
func (r *RoleRepo) Create(ctx context.Context, s iam.TenantScope, role *iam.Role) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO roles (id, organization_id, name, description, is_system)
			VALUES ($1,$2,$3,$4,false)`, role.ID, role.OrganizationID, role.Name, role.Description)
		return mapWriteErr(err)
	})
}

// SetPermissions replaces a role's permissions by key.
func (r *RoleRepo) SetPermissions(ctx context.Context, s iam.TenantScope, roleID iam.ID, keys []string) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, roleID); err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT $1, p.id FROM permissions p WHERE p.key = ANY($2::text[])`, roleID, keys)
		return mapWriteErr(err)
	})
}

// GetDeviceAccess returns a role's resource-level device entitlement: its scope
// plus the granted device types and asset-group ids.
func (r *RoleRepo) GetDeviceAccess(ctx context.Context, s iam.TenantScope, roleID iam.ID) (*iam.RoleDeviceAccess, error) {
	out := &iam.RoleDeviceAccess{Scope: iam.DeviceScopeAll, DeviceTypes: []string{}, GroupIDs: []iam.ID{}}
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		var scope string
		err := tx.QueryRow(ctx, `SELECT device_scope FROM roles WHERE id=$1`, roleID).Scan(&scope)
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		if err != nil {
			return err
		}
		out.Scope = iam.DeviceScope(scope)

		types, err := tx.Query(ctx, `SELECT device_type FROM role_device_types WHERE role_id=$1 ORDER BY device_type`, roleID)
		if err != nil {
			return err
		}
		defer types.Close()
		for types.Next() {
			var t string
			if err := types.Scan(&t); err != nil {
				return err
			}
			out.DeviceTypes = append(out.DeviceTypes, t)
		}
		if err := types.Err(); err != nil {
			return err
		}

		groups, err := tx.Query(ctx, `SELECT asset_group_id FROM role_asset_groups WHERE role_id=$1`, roleID)
		if err != nil {
			return err
		}
		defer groups.Close()
		for groups.Next() {
			var g iam.ID
			if err := groups.Scan(&g); err != nil {
				return err
			}
			out.GroupIDs = append(out.GroupIDs, g)
		}
		return groups.Err()
	})
	return out, err
}

// SetDeviceAccess replaces a role's device scope and its granted device types
// and asset groups (DELETE-then-INSERT, all in one transaction).
func (r *RoleRepo) SetDeviceAccess(ctx context.Context, s iam.TenantScope, roleID iam.ID, access iam.RoleDeviceAccess) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE roles SET device_scope=$2 WHERE id=$1`, roleID, string(access.Scope))
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_device_types WHERE role_id=$1`, roleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_asset_groups WHERE role_id=$1`, roleID); err != nil {
			return err
		}
		if len(access.DeviceTypes) > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO role_device_types (role_id, device_type)
				SELECT $1, unnest($2::text[])
				ON CONFLICT DO NOTHING`, roleID, access.DeviceTypes); err != nil {
				return mapWriteErr(err)
			}
		}
		if len(access.GroupIDs) > 0 {
			// Source the ids from asset_groups rather than inserting them directly:
			// a foreign-key check bypasses RLS, so an FK alone would happily accept
			// another tenant's group id. Selecting through the RLS-protected parent
			// makes an invisible group produce no row, and the count check turns
			// that into an error instead of a silently narrower grant.
			ct, err := tx.Exec(ctx, `
				INSERT INTO role_asset_groups (role_id, asset_group_id)
				SELECT $1, g.id FROM asset_groups g WHERE g.id = ANY($2::uuid[])
				ON CONFLICT DO NOTHING`, roleID, access.GroupIDs)
			if err != nil {
				return mapWriteErr(err)
			}
			if ct.RowsAffected() != int64(len(access.GroupIDs)) {
				return iam.ErrNotFound
			}
		}
		return nil
	})
}

// ListPermissions returns the whole permission catalogue (not tenant-scoped).
func (r *RoleRepo) ListPermissions(ctx context.Context) ([]iam.Permission, error) {
	var out []iam.Permission
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, key, description FROM permissions ORDER BY key`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p iam.Permission
			if err := rows.Scan(&p.ID, &p.Key, &p.Description); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func scanRole(row pgx.Row) (*iam.Role, error) {
	var role iam.Role
	var orgID *iam.ID
	var scope string
	if err := row.Scan(&role.ID, &orgID, &role.Name, &role.Description, &role.IsSystem, &scope, &role.Permissions); err != nil {
		return nil, err
	}
	role.OrganizationID = orgID
	role.DeviceScope = iam.DeviceScope(scope)
	return &role, nil
}
