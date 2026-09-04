package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// DeviceRepo implements assets.DeviceRepository.
type DeviceRepo struct{ db *DB }

// NewDeviceRepo constructs a DeviceRepo.
func NewDeviceRepo(db *DB) *DeviceRepo { return &DeviceRepo{db: db} }

// deviceCols is qualified with the `d` alias because every read LEFT JOINs
// device_health, which shares no column names but is clearer read this way.
const deviceCols = `d.id, d.organization_id, d.name, d.description, d.vendor, d.device_type, d.host, d.port,
	d.scheme, d.verify_tls, d.custom_headers, d.tags, d.status, d.allow_unmanaged,
	d.record_sessions, d.recording_kinds, d.delivery_mode, d.idle_timeout_minutes, d.credential_mode,
	d.requires_approval, d.min_approvals, d.created_by, d.created_at, d.updated_at,
	h.status, h.checked_at, h.latency_ms, h.consecutive_failures, h.last_error`

// deviceFrom is the shared read source: a device plus its liveness, which is
// tracked in a separate table so probing never churns devices.updated_at.
const deviceFrom = ` FROM devices d LEFT JOIN device_health h ON h.device_id = d.id`

// Device reads are filtered to the caller's reach, and carry the level they
// reach each row at. Both come from app_device_reach() (migration 0034), which
// is the single definition of the rule the connect check also uses.
//
// A super admin is exempt: that role exists to read across tenants and already
// bypasses RLS, so filtering it here would be a restriction no other part of the
// system applies to it. Everyone else is filtered, including on a zero UserID —
// which reaches nothing. See the note on assets.Scope.UserID for why that
// direction is the safe one.

// reachLevelCol is the trailing select column carrying the caller's level.
func reachLevelCol(s assets.Scope, argN int) string {
	if s.IsSuperAdmin || s.PostAuthorized {
		return `, 'manage'`
	}
	return `, COALESCE((SELECT app_access_level(r.access_rank) FROM app_device_reach($` +
		strconv.Itoa(argN) + `) r WHERE r.device_id = d.id), 'none')`
}

// reachFilter is the predicate restricting rows to what the caller reaches.
func reachFilter(s assets.Scope, argN int) string {
	if s.IsSuperAdmin || s.PostAuthorized {
		return ""
	}
	return ` AND EXISTS (SELECT 1 FROM app_device_reach($` + strconv.Itoa(argN) +
		`) r WHERE r.device_id = d.id)`
}

// reachArgs is the argument list the two fragments above consume.
func reachArgs(s assets.Scope) []any {
	if s.IsSuperAdmin || s.PostAuthorized {
		return nil
	}
	return []any{s.UserID}
}

func scanDevice(row pgx.Row) (*assets.Device, error) {
	var d assets.Device
	var headers []byte
	// Health columns are all NULL until the poller has seen the device.
	var hStatus, hLastError *string
	var hCheckedAt *time.Time
	var hLatency, hFailures *int
	if err := row.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.Description, &d.Vendor, &d.DeviceType,
		&d.Host, &d.Port, &d.Scheme, &d.VerifyTLS, &headers, &d.Tags, &d.Status,
		&d.AllowUnmanaged, &d.RecordSessions, &d.RecordingKinds, &d.DeliveryMode, &d.IdleTimeoutMinutes,
		&d.CredentialMode, &d.RequiresApproval, &d.MinApprovals, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		&hStatus, &hCheckedAt, &hLatency, &hFailures, &hLastError, &d.AccessLevel); err != nil {
		return nil, err
	}
	if len(headers) > 0 {
		_ = json.Unmarshal(headers, &d.CustomHeaders)
	}
	if hStatus != nil {
		h := assets.Health{Status: assets.HealthStatus(*hStatus), CheckedAt: hCheckedAt, LatencyMS: hLatency}
		if hFailures != nil {
			h.ConsecutiveFailures = *hFailures
		}
		if hLastError != nil {
			h.LastError = *hLastError
		}
		d.Health = &h
	}
	return &d, nil
}

// An unset delivery mode means "not applicable / no isolation", which is what
// the column's own DEFAULT says — but an explicit empty string overrides a
// default, so it reaches the CHECK and the insert fails. Substituting here keeps
// a Device built without the field (any direct repository caller, and every
// integration test) from dying on a constraint instead of getting the sane
// value. The service layer settles this properly via deliveryOrDefault; this is
// the backstop for everything that does not go through it.
//
// Create inserts a device.
func (r *DeviceRepo) Create(ctx context.Context, s assets.Scope, d *assets.Device) error {
	headers := marshalHeaders(d.CustomHeaders)
	tags := nonNilTags(d.Tags)
	kinds := nonNilTags(d.RecordingKinds)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO devices (id, organization_id, name, description, vendor, device_type,
				host, port, scheme, verify_tls, custom_headers, tags, status, allow_unmanaged,
				record_sessions, recording_kinds, delivery_mode, idle_timeout_minutes,
				credential_mode, requires_approval, min_approvals, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
				COALESCE(NULLIF($17,''), 'proxy'), $18,
				COALESCE(NULLIF($19,''), 'shared'), $20, GREATEST($21, 1), $22)`,
			d.ID, d.OrganizationID, d.Name, d.Description, d.Vendor, d.DeviceType,
			d.Host, d.Port, d.Scheme, d.VerifyTLS, headers, tags, d.Status, d.AllowUnmanaged,
			d.RecordSessions, kinds, d.DeliveryMode, d.IdleTimeoutMinutes,
			d.CredentialMode, d.RequiresApproval, d.MinApprovals, d.CreatedBy)
		return mapWriteErr(err)
	})
}

// Update mutates a device.
func (r *DeviceRepo) Update(ctx context.Context, s assets.Scope, d *assets.Device) error {
	headers := marshalHeaders(d.CustomHeaders)
	tags := nonNilTags(d.Tags)
	kinds := nonNilTags(d.RecordingKinds)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE devices SET name=$2, description=$3, vendor=$4, device_type=$5, host=$6,
				port=$7, scheme=$8, verify_tls=$9, custom_headers=$10, tags=$11, status=$12,
				allow_unmanaged=$13, record_sessions=$14, recording_kinds=$15,
				delivery_mode=COALESCE(NULLIF($16,''), 'proxy'), idle_timeout_minutes=$17,
				credential_mode=COALESCE(NULLIF($18,''), 'shared'),
				requires_approval=$19, min_approvals=GREATEST($20, 1)
			WHERE id=$1 AND deleted_at IS NULL`,
			d.ID, d.Name, d.Description, d.Vendor, d.DeviceType, d.Host, d.Port, d.Scheme,
			d.VerifyTLS, headers, tags, d.Status, d.AllowUnmanaged, d.RecordSessions, kinds,
			d.DeliveryMode, d.IdleTimeoutMinutes,
			d.CredentialMode, d.RequiresApproval, d.MinApprovals)
		if err != nil {
			return mapWriteErr(err)
		}
		if ct.RowsAffected() == 0 {
			return assets.ErrNotFound
		}
		return nil
	})
}

// GetByID loads a device within scope.
func (r *DeviceRepo) GetByID(ctx context.Context, s assets.Scope, id uuid.UUID) (*assets.Device, error) {
	var d *assets.Device
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		args := append([]any{id}, reachArgs(s)...)
		row := tx.QueryRow(ctx, `SELECT `+deviceCols+reachLevelCol(s, 2)+deviceFrom+
			` WHERE d.id=$1 AND d.deleted_at IS NULL`+reachFilter(s, 2), args...)
		var e error
		d, e = scanDevice(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return assets.ErrNotFound
		}
		return e
	})
	return d, err
}

// List returns devices matching the filter.
func (r *DeviceRepo) List(ctx context.Context, s assets.Scope, f assets.Filter) ([]assets.Device, error) {
	limit := normalizeLimit(f.Limit)
	var out []assets.Device
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		args := reachArgs(s)
		i := len(args) + 1
		// The reach argument is $1 whenever there is one, so the filter
		// placeholders below start after it.
		q := `SELECT ` + deviceCols + reachLevelCol(s, 1) + deviceFrom +
			` WHERE d.deleted_at IS NULL` + reachFilter(s, 1)
		if f.Vendor != "" {
			q += ` AND d.vendor = $` + strconv.Itoa(i)
			args = append(args, f.Vendor)
			i++
		}
		if f.Tag != "" {
			q += ` AND $` + strconv.Itoa(i) + ` = ANY(d.tags)`
			args = append(args, f.Tag)
			i++
		}
		if f.Search != "" {
			q += ` AND (d.name ILIKE $` + strconv.Itoa(i) + ` OR d.host ILIKE $` + strconv.Itoa(i) + `)`
			args = append(args, "%"+f.Search+"%")
			i++
		}
		q += ` ORDER BY d.name LIMIT $` + strconv.Itoa(i)
		args = append(args, limit)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, e := scanDevice(rows)
			if e != nil {
				return e
			}
			out = append(out, *d)
		}
		return rows.Err()
	})
	return out, err
}

// SoftDelete marks a device deleted.
func (r *DeviceRepo) SoftDelete(ctx context.Context, s assets.Scope, id uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE devices SET deleted_at=now(), status='disabled'
			WHERE id=$1 AND deleted_at IS NULL`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return assets.ErrNotFound
		}
		return nil
	})
}

// marshalHeaders encodes custom headers as a JSON object (never SQL NULL).
func marshalHeaders(h map[string]string) []byte {
	if h == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(h)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// nonNilTags ensures the tags array is non-nil so it satisfies the NOT NULL
// column (a nil slice would be encoded as SQL NULL by pgx).
func nonNilTags(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

// Count returns the number of active devices in scope.
func (r *DeviceRepo) Count(ctx context.Context, s assets.Scope) (int, error) {
	var n int
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices d WHERE d.deleted_at IS NULL`+
			reachFilter(s, 1), reachArgs(s)...).Scan(&n)
	})
	return n, err
}
