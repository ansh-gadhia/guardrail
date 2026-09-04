package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// TeamRepo persists teams, their membership and their device grants.
//
// The three child tables carry no organization_id of their own — RLS on `teams`
// gates which team_id a tenant can reach on read. On WRITE that is not enough:
// a foreign-key check bypasses RLS, so an FK alone would happily accept another
// tenant's user_id or asset_group_id. Every writer here therefore sources its
// ids through the RLS-protected parent table and checks the row count, so an
// id belonging to somebody else produces an error rather than a grant.
type TeamRepo struct{ db *DB }

// NewTeamRepo constructs a TeamRepo.
func NewTeamRepo(db *DB) *TeamRepo { return &TeamRepo{db: db} }

const teamCols = `t.id, t.organization_id, t.name, t.description,
	COALESCE(t.all_devices_level, 'none'), t.created_at, t.updated_at`

func scanTeam(row pgx.Row) (*iam.Team, error) {
	var t iam.Team
	var level string
	if err := row.Scan(&t.ID, &t.OrganizationID, &t.Name, &t.Description,
		&level, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.AllDevicesLevel = iam.AccessLevel(level)
	return &t, nil
}

// Create inserts a team.
func (r *TeamRepo) Create(ctx context.Context, s iam.TenantScope, t *iam.Team) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO teams (organization_id, name, description, all_devices_level)
			VALUES ($1, $2, $3, $4)
			RETURNING id, created_at, updated_at`,
			s.OrganizationID, t.Name, t.Description, nullLevel(t.AllDevicesLevel),
		).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return mapWriteErr(err)
		}
		t.OrganizationID = s.OrganizationID
		return nil
	})
}

// Update renames a team and resets its blanket grant.
func (r *TeamRepo) Update(ctx context.Context, s iam.TenantScope, t *iam.Team) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE teams SET name=$2, description=$3, all_devices_level=$4 WHERE id=$1`,
			t.ID, t.Name, t.Description, nullLevel(t.AllDevicesLevel))
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// Delete removes a team. Membership and grants cascade, so the reach a team
// conferred disappears with it — which is the point of deleting one.
func (r *TeamRepo) Delete(ctx context.Context, s iam.TenantScope, id iam.ID) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM teams WHERE id=$1`, id)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// GetByID returns one team.
func (r *TeamRepo) GetByID(ctx context.Context, s iam.TenantScope, id iam.ID) (*iam.Team, error) {
	var out *iam.Team
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		t, err := scanTeam(tx.QueryRow(ctx, `SELECT `+teamCols+` FROM teams t WHERE t.id=$1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM team_members WHERE team_id=$1`, id).Scan(&t.MemberCount); err != nil {
			return err
		}
		out = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// List returns every team in the organization, with member counts.
func (r *TeamRepo) List(ctx context.Context, s iam.TenantScope) ([]iam.Team, error) {
	out := []iam.Team{}
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+teamCols+`, (SELECT count(*) FROM team_members m WHERE m.team_id = t.id)
			FROM teams t ORDER BY t.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t iam.Team
			var level string
			if err := rows.Scan(&t.ID, &t.OrganizationID, &t.Name, &t.Description,
				&level, &t.CreatedAt, &t.UpdatedAt, &t.MemberCount); err != nil {
				return err
			}
			t.AllDevicesLevel = iam.AccessLevel(level)
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// ListMembers returns a team's membership with each member's email.
func (r *TeamRepo) ListMembers(ctx context.Context, s iam.TenantScope, teamID iam.ID) ([]iam.TeamMember, error) {
	out := []iam.TeamMember{}
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if err := teamExists(ctx, tx, teamID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT tm.user_id, u.email, u.status, tm.added_at
			FROM team_members tm
			JOIN users u ON u.id = tm.user_id AND u.deleted_at IS NULL
			WHERE tm.team_id = $1
			ORDER BY u.email`, teamID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m iam.TeamMember
			if err := rows.Scan(&m.UserID, &m.Email, &m.Status, &m.AddedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// SetMembers replaces a team's membership.
func (r *TeamRepo) SetMembers(ctx context.Context, s iam.TenantScope, teamID iam.ID, userIDs []iam.ID) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if err := teamExists(ctx, tx, teamID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE team_id=$1`, teamID); err != nil {
			return err
		}
		if len(userIDs) == 0 {
			return nil
		}
		// Sourced through `users`, which RLS scopes to this tenant: naming another
		// organization's user id yields no row, and the count check below turns
		// that into an error rather than a silently smaller team.
		ct, err := tx.Exec(ctx, `
			INSERT INTO team_members (team_id, user_id)
			SELECT $1, u.id FROM users u
			WHERE u.id = ANY($2::uuid[]) AND u.deleted_at IS NULL
			ON CONFLICT DO NOTHING`, teamID, userIDs)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() != int64(len(userIDs)) {
			return iam.ErrNotFound
		}
		return nil
	})
}

// ListForUser returns the teams a user belongs to.
func (r *TeamRepo) ListForUser(ctx context.Context, s iam.TenantScope, userID iam.ID) ([]iam.Team, error) {
	out := []iam.Team{}
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+teamCols+`
			FROM teams t
			JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = $1
			ORDER BY t.name`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t iam.Team
			var level string
			if err := rows.Scan(&t.ID, &t.OrganizationID, &t.Name, &t.Description,
				&level, &t.CreatedAt, &t.UpdatedAt); err != nil {
				return err
			}
			t.AllDevicesLevel = iam.AccessLevel(level)
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// GetGrants returns a team's grant set, with group names for rendering.
func (r *TeamRepo) GetGrants(ctx context.Context, s iam.TenantScope, teamID iam.ID) (*iam.TeamGrants, error) {
	out := &iam.TeamGrants{Groups: []iam.GroupGrant{}, DeviceTypes: []iam.TypeGrant{}}
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if err := teamExists(ctx, tx, teamID); err != nil {
			return err
		}
		groups, err := tx.Query(ctx, `
			SELECT tag.asset_group_id, g.name, tag.access_level
			FROM team_asset_groups tag
			JOIN asset_groups g ON g.id = tag.asset_group_id
			WHERE tag.team_id = $1
			ORDER BY g.name`, teamID)
		if err != nil {
			return err
		}
		defer groups.Close()
		for groups.Next() {
			var g iam.GroupGrant
			var level string
			if err := groups.Scan(&g.AssetGroupID, &g.Name, &level); err != nil {
				return err
			}
			g.Level = iam.AccessLevel(level)
			out.Groups = append(out.Groups, g)
		}
		if err := groups.Err(); err != nil {
			return err
		}

		types, err := tx.Query(ctx, `
			SELECT device_type, access_level FROM team_device_types
			WHERE team_id = $1 ORDER BY device_type`, teamID)
		if err != nil {
			return err
		}
		defer types.Close()
		for types.Next() {
			var t iam.TypeGrant
			var level string
			if err := types.Scan(&t.DeviceType, &level); err != nil {
				return err
			}
			t.Level = iam.AccessLevel(level)
			out.DeviceTypes = append(out.DeviceTypes, t)
		}
		return types.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetGrants replaces a team's grant set in one transaction.
func (r *TeamRepo) SetGrants(ctx context.Context, s iam.TenantScope, teamID iam.ID, g iam.TeamGrants) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if err := teamExists(ctx, tx, teamID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM team_asset_groups WHERE team_id=$1`, teamID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM team_device_types WHERE team_id=$1`, teamID); err != nil {
			return err
		}
		if len(g.Groups) > 0 {
			ids := make([]iam.ID, len(g.Groups))
			levels := make([]string, len(g.Groups))
			for i, gr := range g.Groups {
				ids[i], levels[i] = gr.AssetGroupID, string(gr.Level)
			}
			// Same reasoning as SetMembers: sourced through asset_groups so RLS,
			// not the foreign key, decides which ids are reachable.
			ct, err := tx.Exec(ctx, `
				INSERT INTO team_asset_groups (team_id, asset_group_id, access_level)
				SELECT $1, ag.id, v.level
				FROM unnest($2::uuid[], $3::text[]) AS v(gid, level)
				JOIN asset_groups ag ON ag.id = v.gid
				ON CONFLICT DO NOTHING`, teamID, ids, levels)
			if err != nil {
				return mapWriteErr(err)
			}
			if ct.RowsAffected() != int64(len(g.Groups)) {
				return iam.ErrNotFound
			}
		}
		if len(g.DeviceTypes) > 0 {
			types := make([]string, len(g.DeviceTypes))
			levels := make([]string, len(g.DeviceTypes))
			for i, t := range g.DeviceTypes {
				types[i], levels[i] = t.DeviceType, string(t.Level)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO team_device_types (team_id, device_type, access_level)
				SELECT $1, v.dtype, v.level
				FROM unnest($2::text[], $3::text[]) AS v(dtype, level)
				ON CONFLICT DO NOTHING`, teamID, types, levels); err != nil {
				return mapWriteErr(err)
			}
		}
		return nil
	})
}

// teamExists turns an unknown or out-of-tenant team id into ErrNotFound before
// any child-table work happens. Without it a DELETE against the join tables for
// an id RLS hides would report success having changed nothing, and the caller
// would be told a team it cannot see had been updated.
func teamExists(ctx context.Context, tx pgx.Tx, teamID iam.ID) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM teams WHERE id=$1)`, teamID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return iam.ErrNotFound
	}
	return nil
}

// nullLevel maps AccessNone to SQL NULL, which is how "no blanket grant" is
// stored — the CHECK constraint admits only the three real levels.
func nullLevel(l iam.AccessLevel) any {
	if l == "" || l == iam.AccessNone {
		return nil
	}
	return string(l)
}

// Compile-time proof that the repository still satisfies the port. Without it a
// signature drift in the domain shows up as a nil-interface panic at wiring
// time rather than a build failure here.
var _ iam.TeamRepository = (*TeamRepo)(nil)
