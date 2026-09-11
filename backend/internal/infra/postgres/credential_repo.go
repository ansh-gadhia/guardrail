package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/vault"
)

// CredentialRepo implements vault.CredentialRepository. It persists only sealed
// (envelope-encrypted) secret material; no plaintext ever passes through here.
type CredentialRepo struct {
	db *DB
	// signer proves a binding row was written by GuardRail. Optional; see
	// WithBindingSigner.
	signer vault.BindingSigner
}

// NewCredentialRepo constructs a CredentialRepo.
func NewCredentialRepo(db *DB) *CredentialRepo { return &CredentialRepo{db: db} }

// WithBindingSigner attaches the signer that proves a binding row was written by
// GuardRail, and returns the repo so wiring stays a one-liner.
//
// Optional, and nil means every binding is accepted. That is not a policy
// choice, it is what keeps this repo constructible in tests that care about
// credential storage and nothing else; main always sets it.
func (r *CredentialRepo) WithBindingSigner(s vault.BindingSigner) *CredentialRepo {
	r.signer = s
	return r
}

// checkBinding verifies a binding's signature.
//
// An UNSIGNED row is accepted and reported, rather than refused. Every binding
// that existed before 0035 has no signature, and refusing them would break every
// device session on the release that adds this column — a security upgrade that
// takes the estate offline is one that gets rolled back. SignUnsignedBindings
// runs at startup and closes that window; what this must never do is accept a
// signature that is present and WRONG, which is the actual attack.
func (r *CredentialRepo) checkBinding(mac []byte, scope string, parent, credID, userID uuid.UUID) error {
	if r.signer == nil || len(mac) == 0 {
		return nil
	}
	if !r.signer.Verify(mac, scope, parent, credID, userID) {
		return vault.ErrBindingUnsigned
	}
	return nil
}

// macFor computes a binding signature, or nil when no signer is configured.
func (r *CredentialRepo) macFor(scope string, parent, credID uuid.UUID, userID *uuid.UUID) []byte {
	if r.signer == nil {
		return nil
	}
	u := uuid.Nil
	if userID != nil {
		u = *userID
	}
	return r.signer.Sign(scope, parent, credID, u)
}

const credCols = `id, organization_id, name, type, username, injection,
	secret_ciphertext, secret_nonce, dek_wrapped, dek_nonce, kek_id, aad_version, metadata,
	rotated_at, created_at, updated_at`

// credColsC is credCols qualified with the "c." alias for joined queries.
// #nosec G101 -- a SELECT column list. The names describe where ciphertext is
// stored; no secret is present in this string.
const credColsC = `c.id, c.organization_id, c.name, c.type, c.username, c.injection,
	c.secret_ciphertext, c.secret_nonce, c.dek_wrapped, c.dek_nonce, c.kek_id, c.aad_version, c.metadata,
	c.rotated_at, c.created_at, c.updated_at`

func scanCredential(row pgx.Row) (*vault.Credential, error) {
	var c vault.Credential
	var typ, inj string
	var meta []byte
	if err := row.Scan(&c.ID, &c.OrganizationID, &c.Name, &typ, &c.Username, &inj,
		&c.Sealed.Ciphertext, &c.Sealed.SecretNonce, &c.Sealed.DEKWrapped, &c.Sealed.DEKNonce,
		&c.Sealed.KEKID, &c.Sealed.AADVersion, &meta, &c.RotatedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
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
		&c.Sealed.KEKID, &c.Sealed.AADVersion, &meta, &c.RotatedAt, &c.CreatedAt, &c.UpdatedAt}
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
				secret_ciphertext, secret_nonce, dek_wrapped, dek_nonce, kek_id, aad_version, metadata)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			c.ID, c.OrganizationID, c.Name, string(c.Type), c.Username, string(c.Injection),
			c.Sealed.Ciphertext, c.Sealed.SecretNonce, c.Sealed.DEKWrapped, c.Sealed.DEKNonce,
			c.Sealed.KEKID, c.Sealed.AADVersion, meta)
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
				kek_id=$9, aad_version=$10, metadata=$11, rotated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`,
			c.ID, c.Name, c.Username, string(c.Injection),
			c.Sealed.Ciphertext, c.Sealed.SecretNonce, c.Sealed.DEKWrapped, c.Sealed.DEKNonce,
			c.Sealed.KEKID, c.Sealed.AADVersion, meta)
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
			INSERT INTO device_credentials (device_id, credential_id, user_id, binding_mac)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (device_id, credential_id) DO UPDATE
				SET user_id=EXCLUDED.user_id, binding_mac=EXCLUDED.binding_mac`,
			deviceID, credentialID, userID,
			r.macFor(vault.BindingScopeDevice, deviceID, credentialID, userID))
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
			INSERT INTO group_credentials (asset_group_id, credential_id, user_id, binding_mac)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (asset_group_id, credential_id) DO UPDATE
				SET user_id=EXCLUDED.user_id, binding_mac=EXCLUDED.binding_mac`,
			groupID, credentialID, userID,
			r.macFor(vault.BindingScopeGroup, groupID, credentialID, &userID))
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
			var mac []byte
			row := tx.QueryRow(ctx, `SELECT `+credColsC+`, dc.binding_mac
				FROM credentials c
				JOIN device_credentials dc ON dc.credential_id = c.id
				WHERE dc.device_id=$1 AND dc.user_id IS NULL AND c.deleted_at IS NULL
				LIMIT 1`, deviceID)
			c, e := scanCredentialWith(row, &mac)
			if errors.Is(e, pgx.ErrNoRows) {
				return vault.ErrNotFound
			}
			if e != nil {
				return e
			}
			// A shared binding signs uuid.Nil for the user, so it cannot be
			// re-labelled as one person's and keep its signature.
			if e := r.checkBinding(mac, vault.BindingScopeDevice, deviceID, c.ID, uuid.Nil); e != nil {
				return e
			}
			res.Credential = c
			return nil
		}

		// Bound directly to this device for this person.
		var devMAC []byte
		row := tx.QueryRow(ctx, `SELECT `+credColsC+`, dc.binding_mac
			FROM credentials c
			JOIN device_credentials dc ON dc.credential_id = c.id
			WHERE dc.device_id=$1 AND dc.user_id=$2 AND c.deleted_at IS NULL
			LIMIT 1`, deviceID, userID)
		c, e := scanCredentialWith(row, &devMAC)
		if e == nil {
			if ve := r.checkBinding(devMAC, vault.BindingScopeDevice, deviceID, c.ID, userID); ve != nil {
				return ve
			}
			res.Credential, res.PerUser = c, true
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}

		// Inherited from the nearest ancestor group that names this person.
		var groupID uuid.UUID
		var grpMAC []byte
		row = tx.QueryRow(ctx, ancestorsCTE+`
			SELECT `+credColsC+`, gc.asset_group_id, gc.binding_mac
			FROM group_credentials gc
			JOIN up ON up.id = gc.asset_group_id
			JOIN credentials c ON c.id = gc.credential_id
			WHERE gc.user_id = $2 AND c.deleted_at IS NULL
			ORDER BY up.depth
			LIMIT 1`, deviceID, userID)
		c, e = scanCredentialWith(row, &groupID, &grpMAC)
		if errors.Is(e, pgx.ErrNoRows) {
			return vault.ErrNotFound
		}
		if e != nil {
			return e
		}
		// Signed against the GROUP, not the device: one group binding legitimately
		// serves every device in the subtree, which is why the device id cannot be
		// part of what is signed here.
		if ve := r.checkBinding(grpMAC, vault.BindingScopeGroup, groupID, c.ID, userID); ve != nil {
			return ve
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

// SignUnsignedBindings signs every binding that has no signature yet, and
// returns how many it wrote.
//
// This is what lets 0035 ship without an outage. The column arrives NULL on
// every row that already existed, ResolveForDevice accepts an absent signature,
// and this closes that window on the next boot without anybody being asked to
// run anything.
//
// Cross-tenant by necessity — it runs before any request has an organization —
// so it uses the unscoped connection deliberately, and touches only the MAC
// column. Idempotent: a second run finds nothing.
//
// It signs whatever is there, which means a malicious binding inserted before
// this first ran would be blessed. That is inherent to backfilling trust onto
// existing data and is why the migration says so out loud.
func (r *CredentialRepo) SignUnsignedBindings(ctx context.Context) (int, error) {
	if r.signer == nil {
		return 0, nil
	}
	var signed int

	type devRow struct {
		device, cred uuid.UUID
		user         *uuid.UUID
	}
	type grpRow struct {
		group, cred uuid.UUID
		user        uuid.UUID
	}

	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT device_id, credential_id, user_id FROM device_credentials WHERE binding_mac IS NULL`)
		if err != nil {
			return err
		}
		var devs []devRow
		for rows.Next() {
			var d devRow
			if err := rows.Scan(&d.device, &d.cred, &d.user); err != nil {
				rows.Close()
				return err
			}
			devs = append(devs, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		grows, err := tx.Query(ctx,
			`SELECT asset_group_id, credential_id, user_id FROM group_credentials WHERE binding_mac IS NULL`)
		if err != nil {
			return err
		}
		var grps []grpRow
		for grows.Next() {
			var g grpRow
			if err := grows.Scan(&g.group, &g.cred, &g.user); err != nil {
				grows.Close()
				return err
			}
			grps = append(grps, g)
		}
		grows.Close()
		if err := grows.Err(); err != nil {
			return err
		}

		for _, d := range devs {
			mac := r.macFor(vault.BindingScopeDevice, d.device, d.cred, d.user)
			if _, err := tx.Exec(ctx,
				`UPDATE device_credentials SET binding_mac=$3 WHERE device_id=$1 AND credential_id=$2`,
				d.device, d.cred, mac); err != nil {
				return err
			}
			signed++
		}
		for _, g := range grps {
			mac := r.macFor(vault.BindingScopeGroup, g.group, g.cred, &g.user)
			if _, err := tx.Exec(ctx,
				`UPDATE group_credentials SET binding_mac=$3 WHERE asset_group_id=$1 AND credential_id=$2`,
				g.group, g.cred, mac); err != nil {
				return err
			}
			signed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return signed, nil
}

// ListByAADVersion returns credentials sealed under a given associated-data
// rule. Cross-tenant: the re-seal job runs at startup, before any request has an
// organization.
func (r *CredentialRepo) ListByAADVersion(ctx context.Context, version, limit int) ([]vault.Credential, error) {
	limit = normalizeLimit(limit)
	var out []vault.Credential
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+credCols+`
			FROM credentials WHERE aad_version=$1 AND deleted_at IS NULL LIMIT $2`, version, limit)
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
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReplaceSealed swaps the sealed material and nothing else.
//
// Deliberately does NOT touch rotated_at: re-sealing changes how a secret is
// protected, not what it is, and an operator reading "rotated 2 minutes ago"
// off an upgrade would go looking for a password change that never happened.
func (r *CredentialRepo) ReplaceSealed(ctx context.Context, id uuid.UUID, sealed vault.SealedSecret) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE credentials
			SET secret_ciphertext=$2, secret_nonce=$3, dek_wrapped=$4, dek_nonce=$5,
				kek_id=$6, aad_version=$7
			WHERE id=$1 AND deleted_at IS NULL`,
			id, sealed.Ciphertext, sealed.SecretNonce, sealed.DEKWrapped, sealed.DEKNonce,
			sealed.KEKID, sealed.AADVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return vault.ErrNotFound
		}
		return nil
	})
}

// RegisterKEK records a key id in the encryption_keys registry.
//
// credentials.kek_id is a foreign key to this table, so a key that is not
// registered cannot seal anything: the first credential written under it fails
// on the constraint. The id used to be the fixed 'env:1' seeded by migration
// 0003, which made this unnecessary; now that ids are derived from the key,
// a changed master key means a new id that nothing has ever heard of.
//
// Idempotent, and deliberately does not touch `active`: which key is current is
// the provider's answer, not a column's, and two sources for it is how they
// disagree.
func (r *CredentialRepo) RegisterKEK(ctx context.Context, id, provider string) error {
	if id == "" {
		return fmt.Errorf("%w: a KEK id is required", vault.ErrInvalid)
	}
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO encryption_keys (id, provider, alias)
			VALUES ($1, $2, '')
			ON CONFLICT (id) DO NOTHING`, id, provider)
		return err
	})
}

// CountByKEK returns how many live credentials are sealed under a key id.
func (r *CredentialRepo) CountByKEK(ctx context.Context, kekID string) (int, error) {
	var n int
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM credentials WHERE kek_id=$1 AND deleted_at IS NULL`,
			kekID).Scan(&n)
	})
	return n, err
}

// DueForPurge returns credentials soft-deleted before the cutoff, oldest first.
//
// Cross-tenant: retention is a property of the deployment's sweep, and the
// sweep has no organization of its own.
func (r *CredentialRepo) DueForPurge(ctx context.Context, before time.Time, limit int) ([]vault.Credential, error) {
	limit = normalizeLimit(limit)
	var out []vault.Credential
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+credCols+`
			FROM credentials
			WHERE deleted_at IS NOT NULL AND deleted_at < $1
			ORDER BY deleted_at
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
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HardDelete removes a credential and its bindings for good.
//
// Bindings first, and in the same transaction: device_credentials and
// group_credentials reference credentials with ON DELETE RESTRICT, so the
// credential cannot go while a binding names it. Doing both in one transaction
// means there is never a moment where a binding points at nothing.
//
// This is the only place in the product that destroys credential material. It
// is called for rows already soft-deleted past their retention, never on the
// live path.
func (r *CredentialRepo) HardDelete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_credentials WHERE credential_id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM group_credentials WHERE credential_id=$1`, id); err != nil {
			return err
		}
		// The deleted_at guard is not redundant. It is the last thing standing
		// between this function and a live credential if a caller ever passes the
		// wrong id: a row that was never soft-deleted is not eligible, full stop.
		ct, err := tx.Exec(ctx, `DELETE FROM credentials WHERE id=$1 AND deleted_at IS NOT NULL`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return vault.ErrNotFound
		}
		return nil
	})
}
