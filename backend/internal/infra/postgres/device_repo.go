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
	d.record_sessions, d.delivery_mode, d.idle_timeout_minutes, d.created_by, d.created_at, d.updated_at,
	h.status, h.checked_at, h.latency_ms, h.consecutive_failures, h.last_error`

// deviceFrom is the shared read source: a device plus its liveness, which is
// tracked in a separate table so probing never churns devices.updated_at.
const deviceFrom = ` FROM devices d LEFT JOIN device_health h ON h.device_id = d.id`

func scanDevice(row pgx.Row) (*assets.Device, error) {
	var d assets.Device
	var headers []byte
	// Health columns are all NULL until the poller has seen the device.
	var hStatus, hLastError *string
	var hCheckedAt *time.Time
	var hLatency, hFailures *int
	if err := row.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.Description, &d.Vendor, &d.DeviceType,
		&d.Host, &d.Port, &d.Scheme, &d.VerifyTLS, &headers, &d.Tags, &d.Status,
		&d.AllowUnmanaged, &d.RecordSessions, &d.DeliveryMode, &d.IdleTimeoutMinutes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		&hStatus, &hCheckedAt, &hLatency, &hFailures, &hLastError); err != nil {
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

// Create inserts a device.
func (r *DeviceRepo) Create(ctx context.Context, s assets.Scope, d *assets.Device) error {
	headers := marshalHeaders(d.CustomHeaders)
	tags := nonNilTags(d.Tags)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO devices (id, organization_id, name, description, vendor, device_type,
				host, port, scheme, verify_tls, custom_headers, tags, status, allow_unmanaged,
				record_sessions, delivery_mode, idle_timeout_minutes, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			d.ID, d.OrganizationID, d.Name, d.Description, d.Vendor, d.DeviceType,
			d.Host, d.Port, d.Scheme, d.VerifyTLS, headers, tags, d.Status, d.AllowUnmanaged,
			d.RecordSessions, d.DeliveryMode, d.IdleTimeoutMinutes, d.CreatedBy)
		return mapWriteErr(err)
	})
}

// Update mutates a device.
func (r *DeviceRepo) Update(ctx context.Context, s assets.Scope, d *assets.Device) error {
	headers := marshalHeaders(d.CustomHeaders)
	tags := nonNilTags(d.Tags)
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE devices SET name=$2, description=$3, vendor=$4, device_type=$5, host=$6,
				port=$7, scheme=$8, verify_tls=$9, custom_headers=$10, tags=$11, status=$12,
				allow_unmanaged=$13, record_sessions=$14, delivery_mode=$15, idle_timeout_minutes=$16
			WHERE id=$1 AND deleted_at IS NULL`,
			d.ID, d.Name, d.Description, d.Vendor, d.DeviceType, d.Host, d.Port, d.Scheme,
			d.VerifyTLS, headers, tags, d.Status, d.AllowUnmanaged, d.RecordSessions,
			d.DeliveryMode, d.IdleTimeoutMinutes)
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
		row := tx.QueryRow(ctx, `SELECT `+deviceCols+deviceFrom+` WHERE d.id=$1 AND d.deleted_at IS NULL`, id)
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
		q := `SELECT ` + deviceCols + deviceFrom + ` WHERE d.deleted_at IS NULL`
		args := []any{}
		i := 1
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
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE deleted_at IS NULL`).Scan(&n)
	})
	return n, err
}
