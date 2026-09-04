package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// AuthorizerRepo implements access.Authorizer: it answers whether a user's roles
// reach a specific device, by device type or asset-group membership.
type AuthorizerRepo struct{ db *DB }

// NewAuthorizerRepo constructs an AuthorizerRepo.
func NewAuthorizerRepo(db *DB) *AuthorizerRepo { return &AuthorizerRepo{db: db} }

// CanAccessDevice reports whether the user may broker a session to the device.
//
// The rule itself lives in app_device_reach() (migration 0034) and is not
// restated here. It used to be: this function carried its own three-arm UNION
// while the device listing carried none at all, which is how a scoped role came
// to be able to enumerate the entire inventory and be stopped only at the
// Connect button. A rule written down in two places is a rule that will differ
// again, so both callers now select from the same function.
//
// 'connect' is the level required. A team granted 'view' over a group can see
// those devices in the inventory and cannot start a session to them, which is
// the distinction 'view' exists to draw.
func (r *AuthorizerRepo) CanAccessDevice(ctx context.Context, s access.Scope, userID, deviceID uuid.UUID) (bool, error) {
	var ok bool
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM app_device_reach($1)
				WHERE device_id = $2 AND access_rank >= app_access_rank('connect')
			)`, userID, deviceID).Scan(&ok)
	})
	return ok, err
}

// DeviceLevel returns the user's effective reach for one device, or
// iam.AccessNone if they do not reach it at all. It answers "why can this person not
// connect" with something better than a boolean.
func (r *AuthorizerRepo) DeviceLevel(ctx context.Context, s access.Scope, userID, deviceID uuid.UUID) (string, error) {
	level := string(iam.AccessNone)
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COALESCE(
				(SELECT app_access_level(access_rank) FROM app_device_reach($1) WHERE device_id = $2),
				'none')`, userID, deviceID).Scan(&level)
	})
	return level, err
}
