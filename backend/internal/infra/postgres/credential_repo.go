package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/vault"
)

// CredentialRepo implements vault.CredentialRepository. It persists only sealed
// (envelope-encrypted) secret material; no plaintext ever passes through here.
type CredentialRepo struct{ db *DB }

// NewCredentialRepo constructs a CredentialRepo.
func NewCredentialRepo(db *DB) *CredentialRepo { return &CredentialRepo{db: db} }

const credCols = `id, organization_id, name, type, username, injection,
	secret_ciphertext, secret_nonce, dek_wrapped, dek_nonce, kek_id, metadata,
	rotated_at, created_at, updated_at`

// credColsC is credCols qualified with the "c." alias for joined queries.
// #nosec G101 -- a SELECT column list. The names describe where ciphertext is
// stored; no secret is present in this string.
const credColsC = `c.id, c.organization_id, c.name, c.type, c.username, c.injection,
	c.secret_ciphertext, c.secret_nonce, c.dek_wrapped, c.dek_nonce, c.kek_id, c.metadata,
	c.rotated_at, c.created_at, c.updated_at`

func scanCredential(row pgx.Row) (*vault.Credential, error) {
	var c vault.Credential
	var typ, inj string
	var meta []byte
	if err := row.Scan(&c.ID, &c.OrganizationID, &c.Name, &typ, &c.Username, &inj,
		&c.Sealed.Ciphertext, &c.Sealed.SecretNonce, &c.Sealed.DEKWrapped, &c.Sealed.DEKNonce,
		&c.Sealed.KEKID, &meta, &c.RotatedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Type = vault.CredentialType(typ)
	c.Injection = vault.InjectionMethod(inj)
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &c.Metadata)
	}
	return &c, nil
}

// scanCredentialWith scans a credential row that carries extra trailing columns,
// for the joined queries that also return where the binding came from.
func scanCredentialWith(row pgx.Row, extra ...any) (*vault.Credential, error) {
	var c vault.Credential
	var typ, inj string
	var meta []byte
	dest := []any{&c.ID, &c.OrganizationID, &c.Name, &typ, &c.Username, &inj,
		&c.Sealed.Ciphertext, &c.Sealed.SecretNonce, &c.Sealed.DEKWrapped, &c.Sealed.DEKNonce,
		&c.Sealed.KEKID, &meta, &c.RotatedAt, &c.CreatedAt, &c.UpdatedAt}
	dest = append(dest, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	c.Type = vault.CredentialType(typ)
	c.Injection = vault.InjectionMethod(inj)
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &c.Metadata)
	}
	return &c, nil
}

// Create inserts a sealed credential.
func (r *CredentialRepo) Create(ctx context.Context, s vault.Scope, c *vault.Credential) error {
	meta, _ := json.Marshal(c.Metadata)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO credentials (id, organization_id, name, type, username, injection,
				secret_ciphertext, secret_nonce, dek_wrapped, dek_nonce, kek_id, metadata)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			c.ID, c.OrganizationID, c.Name, string(c.Type), c.Username, string(c.Injection),
			c.Sealed.Ciphertext, c.Sealed.SecretNonce, c.Sealed.DEKWrapped, c.Sealed.DEKNonce,
			c.Sealed.KEKID, meta)
		return mapWriteErr(err)
	})
}

// Update rotates the sealed secret and/or metadata of an existing credential.
func (r *CredentialRepo) Update(ctx context.Context, s vault.Scope, c *vault.Credential) error {
	meta, _ := json.Marshal(c.Metadata)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE credentials SET name=$2, username=$3, injection=$4,
				secret_ciphertext=$5, secret_nonce=$6, dek_wrapped=$7, dek_nonce=$8,
				kek_id=$9, metadata=$10, rotated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`,
			c.ID, c.Name, c.Username, string(c.Injection),
			c.Sealed.Ciphertext, c.Sealed.SecretNonce, c.Sealed.DEKWrapped, c.Sealed.DEKNonce,
			c.Sealed.KEKID, meta)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return vault.ErrNotFound
		}
		return nil
	})
}

// GetByID loads a sealed credential (metadata + envelope, never plaintext).
func (r *CredentialRepo) GetByID(ctx context.Context, s vault.Scope, id uuid.UUID) (*vault.Credential, error) {
	var c *vault.Credential
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+credCols+` FROM credentials WHERE id=$1 AND deleted_at IS NULL`, id)
		var e error
		c, e = scanCredential(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return vault.ErrNotFound
		}
		return e
	})
	return c, err
}

// List returns sealed credentials in scope.
func (r *CredentialRepo) List(ctx context.Context, s vault.Scope, limit int) ([]vault.Credential, error) {
	limit = normalizeLimit(limit)
	var out []vault.Credential
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+credCols+`
			FROM credentials WHERE deleted_at IS NULL ORDER BY name LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, e := scanCredential(rows)
			if e != nil {
				return e
			}
			out = append(out, *c)
		}
		return rows.Err()
	})
	return out, err
}

// SoftDelete marks a credential deleted.
func (r *CredentialRepo) SoftDelete(ctx context.Context, s vault.Scope, id uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE credentials SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return vault.ErrNotFound
		}
		return nil
	})
}

// ancestorsCTE walks UP the asset-group tree from a device's direct groups,
// recording how far each ancestor is. Nearest wins, so a credential bound at
// "Datacentre / Core" beats one bound at "Datacentre".
//
// The depth ceiling is not decoration: parent_id is a plain self-reference with
// nothing stopping a cycle, and a recursive CTE that meets one never returns.
// Sixteen is far deeper than any real asset tree.
const ancestorsCTE = `
	WITH RECURSIVE up (id, parent_id, depth) AS (
		SELECT g.id, g.parent_id, 0
		FROM asset_groups g
		JOIN device_group_members m ON m.asset_group_id = g.id
		WHERE m.device_id = $1
	  UNION ALL
		SELECT p.id, p.parent_id, up.depth + 1
		FROM asset_groups p
		JOIN up ON up.parent_id = p.id
		WHERE up.depth < 16
	)`

// BindToDevice attaches a credential to a device. A nil userID makes it the
// device's shared credential; a non-nil one makes it that person's account.
func (r *CredentialRepo) BindToDevice(ctx context.Context, s vault.Scope, deviceID, credentialID uuid.UUID, userID *uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		// The device id is sourced through the RLS-protected devices table rather
		// than trusted from the caller: device_credentials has no organization_id
		// of its own, and a foreign key does not enforce the tenant boundary
		// because FK checks bypass RLS.
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE id=$1 AND deleted_at IS NULL)`,
			deviceID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return vault.ErrNotFound
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO device_credentials (device_id, credential_id, user_id)
			VALUES ($1,$2,$3)
			ON CONFLICT (device_id, credential_id) DO UPDATE SET user_id=EXCLUDED.user_id`,
			deviceID, credentialID, userID)
		return mapWriteErr(err)
	})
}

// UnbindFromDevice removes a binding. A nil userID removes the shared one.
func (r *CredentialRepo) UnbindFromDevice(ctx context.Context, s vault.Scope, deviceID uuid.UUID, userID *uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			DELETE FROM device_credentials
			WHERE device_id=$1 AND user_id IS NOT DISTINCT FROM $2`, deviceID, userID)
		return err
	})
}

// BindToGroup attaches a person's credential to an asset group's subtree.
func (r *CredentialRepo) BindToGroup(ctx context.Context, s vault.Scope, groupID, credentialID, userID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		// Sourced through RLS-protected asset_groups, for the reason in
		// BindToDevice: the FK alone would accept another tenant's group id.
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_groups WHERE id=$1)`, groupID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return vault.ErrNotFound
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO group_credentials (asset_group_id, credential_id, user_id)
			VALUES ($1,$2,$3)
			ON CONFLICT (asset_group_id, credential_id) DO UPDATE SET user_id=EXCLUDED.user_id`,
			groupID, credentialID, userID)
		return mapWriteErr(err)
	})
}

// UnbindFromGroup removes a person's binding from a group.
func (r *CredentialRepo) UnbindFromGroup(ctx context.Context, s vault.Scope, groupID, userID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM group_credentials WHERE asset_group_id=$1 AND user_id=$2`, groupID, userID)
		return err
	})
}

// ResolveForDevice returns the sealed credential to inject for this user on this
// device, applying the device's credential_mode.
//
// Order for a per_user device: the binding on the device itself, then the
// nearest group binding walking up the tree. There is deliberately NO fallback
// to the shared credential — a quiet fallback would log somebody into the device
// as the shared admin account when they were supposed to appear in its logs
// under their own name, destroying the attribution the mode exists to create.
func (r *CredentialRepo) ResolveForDevice(ctx context.Context, s vault.Scope, deviceID, userID uuid.UUID) (*vault.Resolution, error) {
	res := &vault.Resolution{}
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		var perUser bool
		if err := tx.QueryRow(ctx,
			`SELECT credential_mode = 'per_user' FROM devices WHERE id=$1 AND deleted_at IS NULL`,
			deviceID).Scan(&perUser); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return vault.ErrNotFound
			}
			return err
		}

		if !perUser {
			row := tx.QueryRow(ctx, `SELECT `+credColsC+`
				FROM credentials c
				JOIN device_credentials dc ON dc.credential_id = c.id
				WHERE dc.device_id=$1 AND dc.user_id IS NULL AND c.deleted_at IS NULL
				LIMIT 1`, deviceID)
			c, e := scanCredential(row)
			if errors.Is(e, pgx.ErrNoRows) {
				return vault.ErrNotFound
			}
			if e != nil {
				return e
			}
			res.Credential = c
			return nil
		}

		// Bound directly to this device for this person.
		row := tx.QueryRow(ctx, `SELECT `+credColsC+`
			FROM credentials c
			JOIN device_credentials dc ON dc.credential_id = c.id
			WHERE dc.device_id=$1 AND dc.user_id=$2 AND c.deleted_at IS NULL
			LIMIT 1`, deviceID, userID)
		c, e := scanCredential(row)
		if e == nil {
			res.Credential, res.PerUser = c, true
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}

		// Inherited from the nearest ancestor group that names this person.
		var groupID uuid.UUID
		row = tx.QueryRow(ctx, ancestorsCTE+`
			SELECT `+credColsC+`, gc.asset_group_id
			FROM group_credentials gc
			JOIN up ON up.id = gc.asset_group_id
			JOIN credentials c ON c.id = gc.credential_id
			WHERE gc.user_id = $2 AND c.deleted_at IS NULL
			ORDER BY up.depth
			LIMIT 1`, deviceID, userID)
		c, e = scanCredentialWith(row, &groupID)
		if errors.Is(e, pgx.ErrNoRows) {
			return vault.ErrNotFound
		}
		if e != nil {
			return e
		}
		res.Credential, res.PerUser, res.Inherited, res.GroupID = c, true, true, &groupID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// HasCredentialForDevice reports whether this user would get a credential on this
// device. No secret material is read and no audit is emitted.
//
// It branches on credential_mode in the same query as ResolveForDevice on
// purpose: a pre-flight that answers a different question from the resolution it
// guards is worse than no pre-flight, because it lets the session get created
// before the failure surfaces.
func (r *CredentialRepo) HasCredentialForDevice(ctx context.Context, s vault.Scope, deviceID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, ancestorsCTE+`
			SELECT CASE
				WHEN (SELECT credential_mode FROM devices WHERE id=$1) = 'per_user' THEN
					EXISTS (
						SELECT 1 FROM device_credentials dc
						JOIN credentials c ON c.id = dc.credential_id
						WHERE dc.device_id=$1 AND dc.user_id=$2 AND c.deleted_at IS NULL
					) OR EXISTS (
						SELECT 1 FROM group_credentials gc
						JOIN up ON up.id = gc.asset_group_id
						JOIN credentials c ON c.id = gc.credential_id
						WHERE gc.user_id=$2 AND c.deleted_at IS NULL
					)
				ELSE
					EXISTS (
						SELECT 1 FROM device_credentials dc
						JOIN credentials c ON c.id = dc.credential_id
						WHERE dc.device_id=$1 AND dc.user_id IS NULL AND c.deleted_at IS NULL
					)
			END`, deviceID, userID).Scan(&exists)
	})
	return exists, err
}

// DeviceIDsProvisioned returns the subset of deviceIDs that somebody can connect
// to: a shared credential on a shared device, or at least one per-user account
// (bound directly or inherited) on a per-user device.
//
// Not per viewer. See the port for why.
func (r *CredentialRepo) DeviceIDsProvisioned(ctx context.Context, s vault.Scope, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	out := make(map[uuid.UUID]bool, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return out, nil
	}
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH RECURSIVE up (device_id, id, parent_id, depth) AS (
				SELECT m.device_id, g.id, g.parent_id, 0
				FROM asset_groups g
				JOIN device_group_members m ON m.asset_group_id = g.id
				WHERE m.device_id = ANY($1)
			  UNION ALL
				SELECT up.device_id, p.id, p.parent_id, up.depth + 1
				FROM asset_groups p
				JOIN up ON up.parent_id = p.id
				WHERE up.depth < 16
			)
			SELECT d.id FROM devices d
			WHERE d.id = ANY($1) AND d.deleted_at IS NULL AND (
				CASE WHEN d.credential_mode = 'per_user' THEN
					EXISTS (
						SELECT 1 FROM device_credentials dc
						JOIN credentials c ON c.id = dc.credential_id
						WHERE dc.device_id=d.id AND dc.user_id IS NOT NULL AND c.deleted_at IS NULL
					) OR EXISTS (
						SELECT 1 FROM group_credentials gc
						JOIN up ON up.id = gc.asset_group_id AND up.device_id = d.id
						JOIN credentials c ON c.id = gc.credential_id
						WHERE c.deleted_at IS NULL
					)
				ELSE
					EXISTS (
						SELECT 1 FROM device_credentials dc
						JOIN credentials c ON c.id = dc.credential_id
						WHERE dc.device_id=d.id AND dc.user_id IS NULL AND c.deleted_at IS NULL
					)
				END
			)`, deviceIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}

const bindingCols = `c.id, c.name, c.username, c.injection, c.rotated_at, c.created_at`

func scanBinding(row pgx.Row, b *vault.Binding) error {
	var inj string
	if err := row.Scan(&b.CredentialID, &b.CredentialName, &b.Username, &inj,
		&b.RotatedAt, &b.CreatedAt, &b.UserID, &b.UserEmail); err != nil {
		return err
	}
	b.Injection = vault.InjectionMethod(inj)
	return nil
}

// ListDeviceBindings returns every binding attached directly to a device.
func (r *CredentialRepo) ListDeviceBindings(ctx context.Context, s vault.Scope, deviceID uuid.UUID) ([]vault.Binding, error) {
	var out []vault.Binding
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+bindingCols+`, dc.user_id, COALESCE(u.email::text, '')
			FROM device_credentials dc
			JOIN credentials c ON c.id = dc.credential_id
			LEFT JOIN users u ON u.id = dc.user_id
			WHERE dc.device_id=$1 AND c.deleted_at IS NULL
			ORDER BY dc.user_id NULLS FIRST, u.email`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b vault.Binding
			if e := scanBinding(rows, &b); e != nil {
				return e
			}
			d := deviceID
			b.DeviceID = &d
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// ListInheritedBindings returns the group bindings a device inherits, nearest
// ancestor first — what the console shows as "inherited from Datacentre / Core".
func (r *CredentialRepo) ListInheritedBindings(ctx context.Context, s vault.Scope, deviceID uuid.UUID) ([]vault.Binding, error) {
	var out []vault.Binding
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, ancestorsCTE+`
			SELECT `+bindingCols+`, gc.user_id, COALESCE(u.email::text, ''), gc.asset_group_id, g.name
			FROM group_credentials gc
			JOIN up ON up.id = gc.asset_group_id
			JOIN asset_groups g ON g.id = gc.asset_group_id
			JOIN credentials c ON c.id = gc.credential_id
			LEFT JOIN users u ON u.id = gc.user_id
			WHERE c.deleted_at IS NULL
			ORDER BY up.depth, u.email`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b vault.Binding
			var gid uuid.UUID
			var inj string
			if e := rows.Scan(&b.CredentialID, &b.CredentialName, &b.Username, &inj, &b.RotatedAt,
				&b.CreatedAt, &b.UserID, &b.UserEmail, &gid, &b.GroupName); e != nil {
				return e
			}
			b.Injection = vault.InjectionMethod(inj)
			b.GroupID = &gid
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// ListGroupBindings returns every binding attached to an asset group.
func (r *CredentialRepo) ListGroupBindings(ctx context.Context, s vault.Scope, groupID uuid.UUID) ([]vault.Binding, error) {
	var out []vault.Binding
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+bindingCols+`, gc.user_id, COALESCE(u.email::text, '')
			FROM group_credentials gc
			JOIN credentials c ON c.id = gc.credential_id
			LEFT JOIN users u ON u.id = gc.user_id
			WHERE gc.asset_group_id=$1 AND c.deleted_at IS NULL
			ORDER BY u.email`, groupID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b vault.Binding
			if e := scanBinding(rows, &b); e != nil {
				return e
			}
			g := groupID
			b.GroupID = &g
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// ListUserBindings returns every binding owned by one person, device and group
// alike, for the per-user account listing and for offboarding.
func (r *CredentialRepo) ListUserBindings(ctx context.Context, s vault.Scope, userID uuid.UUID) ([]vault.Binding, error) {
	var out []vault.Binding
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+bindingCols+`, dc.user_id, dc.device_id, NULL::uuid, COALESCE(d.name, '')
			FROM device_credentials dc
			JOIN credentials c ON c.id = dc.credential_id
			JOIN devices d ON d.id = dc.device_id
			WHERE dc.user_id=$1 AND c.deleted_at IS NULL AND d.deleted_at IS NULL
			UNION ALL
			SELECT `+bindingCols+`, gc.user_id, NULL::uuid, gc.asset_group_id, g.name
			FROM group_credentials gc
			JOIN credentials c ON c.id = gc.credential_id
			JOIN asset_groups g ON g.id = gc.asset_group_id
			WHERE gc.user_id=$1 AND c.deleted_at IS NULL
			ORDER BY 2`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b vault.Binding
			var inj, label string
			if e := rows.Scan(&b.CredentialID, &b.CredentialName, &b.Username, &inj, &b.RotatedAt,
				&b.CreatedAt, &b.UserID, &b.DeviceID, &b.GroupID, &label); e != nil {
				return e
			}
			b.Injection = vault.InjectionMethod(inj)
			b.GroupName = label
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// CredentialIDsForUser returns the credentials owned by one person.
func (r *CredentialRepo) CredentialIDsForUser(ctx context.Context, s vault.Scope, userID uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT c.id FROM credentials c
			WHERE c.deleted_at IS NULL AND (
				c.id IN (SELECT credential_id FROM device_credentials WHERE user_id=$1)
				OR c.id IN (SELECT credential_id FROM group_credentials WHERE user_id=$1))`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// StaleCredentials returns credentials whose secret has not been rotated since
// `before`. A credential that has never been rotated is measured from creation:
// "never rotated" and "rotated long ago" are the same risk, and treating the
// first as unknown would hide the oldest secrets in the vault.
func (r *CredentialRepo) StaleCredentials(ctx context.Context, s vault.Scope, before time.Time, limit int) ([]vault.Credential, error) {
	limit = normalizeLimit(limit)
	var out []vault.Credential
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+credCols+`
			FROM credentials
			WHERE deleted_at IS NULL AND COALESCE(rotated_at, created_at) < $1
			ORDER BY COALESCE(rotated_at, created_at)
			LIMIT $2`, before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, e := scanCredential(rows)
			if e != nil {
				return e
			}
			out = append(out, *c)
		}
		return rows.Err()
	})
	return out, err
}

// ListByKEK returns sealed credentials under a given KEK across all tenants,
// for the rotation job (system scope).
func (r *CredentialRepo) ListByKEK(ctx context.Context, kekID string, limit int) ([]vault.Credential, error) {
	limit = normalizeLimit(limit)
	var out []vault.Credential
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+credCols+`
			FROM credentials WHERE kek_id=$1 AND deleted_at IS NULL LIMIT $2`, kekID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, e := scanCredential(rows)
			if e != nil {
				return e
			}
			out = append(out, *c)
		}
		return rows.Err()
	})
	return out, err
}
