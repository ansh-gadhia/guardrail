package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// AuthorizerRepo implements access.Authorizer: it answers whether a user's roles
// reach a specific device, by device type or asset-group membership.
type AuthorizerRepo struct{ db *DB }

// NewAuthorizerRepo constructs an AuthorizerRepo.
func NewAuthorizerRepo(db *DB) *AuthorizerRepo { return &AuthorizerRepo{db: db} }

// CanAccessDevice reports whether the user is entitled to broker a session to the
// device. Access is granted if any of the user's roles is unrestricted
// (device_scope='all'), or — for a 'scoped' role — the device's type is in that
// role's allowed types, or the device belongs to one of that role's asset groups.
// The whole check is a single indexed EXISTS keyed on user_id + device_id.
func (r *AuthorizerRepo) CanAccessDevice(ctx context.Context, s access.Scope, userID, deviceID uuid.UUID) (bool, error) {
	var ok bool
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				-- an unrestricted role reaches every device in the org
				SELECT 1
				FROM user_roles ur
				JOIN roles r ON r.id = ur.role_id AND r.device_scope = 'all'
				WHERE ur.user_id = $1
				UNION ALL
				-- a scoped role that allows this device's type
				SELECT 1
				FROM user_roles ur
				JOIN roles r ON r.id = ur.role_id AND r.device_scope = 'scoped'
				JOIN role_device_types rdt ON rdt.role_id = r.id
				JOIN devices d ON d.id = $2 AND lower(d.device_type) = lower(rdt.device_type)
				WHERE ur.user_id = $1
				UNION ALL
				-- a scoped role that grants a group the device belongs to
				SELECT 1
				FROM user_roles ur
				JOIN roles r ON r.id = ur.role_id AND r.device_scope = 'scoped'
				JOIN role_asset_groups rag ON rag.role_id = r.id
				JOIN device_group_members dgm ON dgm.asset_group_id = rag.asset_group_id
					AND dgm.device_id = $2
				WHERE ur.user_id = $1
			)`, userID, deviceID).Scan(&ok)
	})
	return ok, err
}
