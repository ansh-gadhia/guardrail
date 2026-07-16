package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// UserRepo implements iam.UserRepository.
type UserRepo struct{ db *DB }

// NewUserRepo constructs a UserRepo.
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

const userColumns = `id, organization_id, email, COALESCE(username,''), COALESCE(password_hash,''),
	auth_provider, status, is_super_admin, failed_login_count, locked_until, last_login_at,
	must_change_password, created_at, updated_at`

func scanUser(row pgx.Row) (*iam.User, error) {
	var u iam.User
	var email string
	if err := row.Scan(&u.ID, &u.OrganizationID, &email, &u.Username, &u.PasswordHash,
		&u.AuthProvider, &u.Status, &u.IsSuperAdmin, &u.FailedLoginCount,
		&u.LockedUntil, &u.LastLoginAt, &u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	u.Email = iam.Email(email)
	return &u, nil
}

// Create inserts a new user.
func (r *UserRepo) Create(ctx context.Context, s iam.TenantScope, u *iam.User) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO users (id, organization_id, email, username, password_hash,
				auth_provider, status, is_super_admin, must_change_password)
			VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9)`,
			u.ID, u.OrganizationID, u.Email.String(), u.Username, u.PasswordHash,
			string(u.AuthProvider), u.Status, u.IsSuperAdmin, u.MustChangePassword)
		if err != nil {
			return mapWriteErr(err)
		}
		return nil
	})
}

// Update mutates core user fields (not password/login counters).
func (r *UserRepo) Update(ctx context.Context, s iam.TenantScope, u *iam.User) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE users SET username=NULLIF($2,''), status=$3, updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`,
			u.ID, u.Username, u.Status)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// GetByID loads a user with roles/permissions within the tenant scope.
func (r *UserRepo) GetByID(ctx context.Context, s iam.TenantScope, id iam.ID) (*iam.User, error) {
	var u *iam.User
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id=$1 AND deleted_at IS NULL`, id)
		var e error
		u, e = scanUser(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		if e != nil {
			return e
		}
		return loadRoles(ctx, tx, []*iam.User{u})
	})
	return u, err
}

// List returns users in the tenant (roles loaded).
func (r *UserRepo) List(ctx context.Context, s iam.TenantScope, page iam.Page) ([]iam.User, error) {
	limit := normalizeLimit(page.Limit)
	var out []iam.User
	err := r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userColumns+`
			FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		var ptrs []*iam.User
		for rows.Next() {
			u, e := scanUser(rows)
			if e != nil {
				return e
			}
			ptrs = append(ptrs, u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := loadRoles(ctx, tx, ptrs); err != nil {
			return err
		}
		out = make([]iam.User, 0, len(ptrs))
		for _, p := range ptrs {
			out = append(out, *p)
		}
		return nil
	})
	return out, err
}

// SoftDelete marks a user deleted.
func (r *UserRepo) SoftDelete(ctx context.Context, s iam.TenantScope, id iam.ID) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE users SET deleted_at=now(), status='disabled'
			WHERE id=$1 AND deleted_at IS NULL`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return iam.ErrNotFound
		}
		return nil
	})
}

// GetByEmailGlobal resolves candidate active users by email across tenants
// (pre-auth, RLS bypassed for this trusted read).
func (r *UserRepo) GetByEmailGlobal(ctx context.Context, email iam.Email) ([]iam.User, error) {
	var out []iam.User
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userColumns+`
			FROM users WHERE email=$1 AND deleted_at IS NULL`, email.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		var ptrs []*iam.User
		for rows.Next() {
			u, e := scanUser(rows)
			if e != nil {
				return e
			}
			ptrs = append(ptrs, u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := loadRoles(ctx, tx, ptrs); err != nil {
			return err
		}
		for _, p := range ptrs {
			out = append(out, *p)
		}
		return nil
	})
	return out, err
}

// GetByEmailInOrg resolves a single user within a known organization (pre-auth).
func (r *UserRepo) GetByEmailInOrg(ctx context.Context, orgID iam.ID, email iam.Email) (*iam.User, error) {
	var u *iam.User
	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+userColumns+`
			FROM users WHERE organization_id=$1 AND email=$2 AND deleted_at IS NULL`,
			orgID, email.String())
		var e error
		u, e = scanUser(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return iam.ErrNotFound
		}
		if e != nil {
			return e
		}
		return loadRoles(ctx, tx, []*iam.User{u})
	})
	return u, err
}

// SetRoles replaces the user's role assignments.
func (r *UserRepo) SetRoles(ctx context.Context, s iam.TenantScope, userID iam.ID, roleIDs []iam.ID) error {
	return r.db.withScope(ctx, s, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1`, userID); err != nil {
			return err
		}
		for _, rid := range roleIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2)`, userID, rid); err != nil {
				return mapWriteErr(err)
			}
		}
		return nil
	})
}

// RecordLoginSuccess resets counters and stamps last_login_at (system scope:
// this runs right after authentication, before a token exists).
func (r *UserRepo) RecordLoginSuccess(ctx context.Context, userID iam.ID, at time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users
			SET failed_login_count=0, locked_until=NULL, last_login_at=$2 WHERE id=$1`, userID, at)
		return err
	})
}

// RecordLoginFailure increments the failure counter and applies an optional lock.
func (r *UserRepo) RecordLoginFailure(ctx context.Context, userID iam.ID, lockUntil *time.Time) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users
			SET failed_login_count=failed_login_count+1, locked_until=$2 WHERE id=$1`, userID, lockUntil)
		return err
	})
}

// UpdatePasswordHash sets a new password hash (rehash-on-login, password change).
func (r *UserRepo) UpdatePasswordHash(ctx context.Context, userID iam.ID, hash string) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, hash)
		return err
	})
}

// SetMustChangePassword raises or clears the forced-password-change flag. Like
// UpdatePasswordHash it runs system-scoped: the user changing their own password
// at first sign-in is acting on themselves, and the flag is keyed by user id.
func (r *UserRepo) SetMustChangePassword(ctx context.Context, userID iam.ID, must bool) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET must_change_password=$2, updated_at=now() WHERE id=$1`, userID, must)
		return err
	})
}

// loadRoles hydrates roles + permission keys for the given users in one query.
func loadRoles(ctx context.Context, tx pgx.Tx, users []*iam.User) error {
	if len(users) == 0 {
		return nil
	}
	ids := make([]string, 0, len(users))
	index := make(map[string]*iam.User, len(users))
	for _, u := range users {
		s := u.ID.String()
		ids = append(ids, s)
		index[s] = u
	}
	rows, err := tx.Query(ctx, `
		SELECT ur.user_id, r.id, r.name, r.description, r.is_system,
			COALESCE(array_agg(p.key) FILTER (WHERE p.key IS NOT NULL), '{}') AS perms
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = ANY($1::uuid[])
		GROUP BY ur.user_id, r.id, r.name, r.description, r.is_system`, ids)
	if err != nil {
		return fmt.Errorf("postgres: load roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var userID, roleID iam.ID
		var role iam.Role
		if err := rows.Scan(&userID, &roleID, &role.Name, &role.Description, &role.IsSystem, &role.Permissions); err != nil {
			return err
		}
		role.ID = roleID
		if u, ok := index[userID.String()]; ok {
			u.Roles = append(u.Roles, role)
		}
	}
	return rows.Err()
}
