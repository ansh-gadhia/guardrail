package postgres

import (
	"context"
	"encoding/json"
	"errors"

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

// BindToDevice associates a credential with a device (optionally as default).
func (r *CredentialRepo) BindToDevice(ctx context.Context, s vault.Scope, deviceID, credentialID uuid.UUID, isDefault bool) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		if isDefault {
			if _, err := tx.Exec(ctx, `UPDATE device_credentials SET is_default=false WHERE device_id=$1`, deviceID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO device_credentials (device_id, credential_id, is_default)
			VALUES ($1,$2,$3)
			ON CONFLICT (device_id, credential_id) DO UPDATE SET is_default=EXCLUDED.is_default`,
			deviceID, credentialID, isDefault)
		return mapWriteErr(err)
	})
}

// ResolveForDevice returns the default (or first) sealed credential bound to a
// device, for just-in-time injection by the gateway.
func (r *CredentialRepo) ResolveForDevice(ctx context.Context, s vault.Scope, deviceID uuid.UUID) (*vault.Credential, error) {
	var c *vault.Credential
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+credColsC+`
			FROM credentials c
			JOIN device_credentials dc ON dc.credential_id = c.id
			WHERE dc.device_id=$1 AND c.deleted_at IS NULL
			ORDER BY dc.is_default DESC, c.created_at
			LIMIT 1`, deviceID)
		var e error
		c, e = scanCredential(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return vault.ErrNotFound
		}
		return e
	})
	return c, err
}

// HasCredentialForDevice reports whether a device has at least one bound,
// non-deleted credential. No secret material is read and no audit is emitted.
func (r *CredentialRepo) HasCredentialForDevice(ctx context.Context, s vault.Scope, deviceID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM device_credentials dc
				JOIN credentials c ON c.id = dc.credential_id
				WHERE dc.device_id = $1 AND c.deleted_at IS NULL
			)`, deviceID).Scan(&exists)
	})
	return exists, err
}

// DeviceIDsWithCredential returns the subset of deviceIDs that have at least one
// bound, non-deleted credential. Returns an empty (non-nil) map for no input.
func (r *CredentialRepo) DeviceIDsWithCredential(ctx context.Context, s vault.Scope, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	out := make(map[uuid.UUID]bool, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return out, nil
	}
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT dc.device_id
			FROM device_credentials dc
			JOIN credentials c ON c.id = dc.credential_id
			WHERE c.deleted_at IS NULL AND dc.device_id = ANY($1)`, deviceIDs)
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
