package postgres

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// AccessSessionRepo implements access.SessionRepository.
type AccessSessionRepo struct{ db *DB }

// NewAccessSessionRepo constructs an AccessSessionRepo.
func NewAccessSessionRepo(db *DB) *AccessSessionRepo { return &AccessSessionRepo{db: db} }

const sessCols = `id, organization_id, user_id, device_id,
	COALESCE(device_name,''), COALESCE(device_type,''), COALESCE(device_address,''),
	protocol, status,
	granted_from, granted_until, COALESCE(host(client_ip),''), COALESCE(user_agent,''),
	COALESCE(gateway_node,''), started_at, ended_at, COALESCE(end_reason,''), created_at,
	COALESCE(watermark,''), last_activity_at`

func scanSession(row pgx.Row) (*access.Session, error) {
	var s access.Session
	var proto, status string
	if err := row.Scan(&s.ID, &s.OrganizationID, &s.UserID, &s.DeviceID,
		&s.DeviceName, &s.DeviceType, &s.DeviceAddress, &proto, &status,
		&s.GrantedFrom, &s.GrantedUntil, &s.ClientIP, &s.UserAgent,
		&s.GatewayNode, &s.StartedAt, &s.EndedAt, &s.EndReason, &s.CreatedAt,
		// Empty for a session predating the column; WatermarkOr then falls back to
		// the session id, which is what those sessions were actually drawn with.
		&s.Watermark, &s.LastActivityAt); err != nil {
		return nil, err
	}
	s.Protocol = access.Protocol(proto)
	s.Status = access.Status(status)
	return &s, nil
}

// Create inserts an access session.
func (r *AccessSessionRepo) Create(ctx context.Context, sc access.Scope, s *access.Session) error {
	return r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO access_sessions (id, organization_id, user_id, device_id, protocol,
				status, granted_from, granted_until, client_ip, user_agent,
				gateway_node, started_at, watermark,
				device_name, device_type, device_address)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::inet,$10,$11,$12,NULLIF($13,''),
				NULLIF($14,''),NULLIF($15,''),NULLIF($16,''))`,
			s.ID, s.OrganizationID, s.UserID, s.DeviceID, string(s.Protocol), string(s.Status),
			s.GrantedFrom, s.GrantedUntil, s.ClientIP, s.UserAgent,
			s.GatewayNode, s.StartedAt, s.Watermark,
			s.DeviceName, s.DeviceType, s.DeviceAddress)
		return mapWriteErr(err)
	})
}

// GetByID loads a session in scope.
func (r *AccessSessionRepo) GetByID(ctx context.Context, sc access.Scope, id uuid.UUID) (*access.Session, error) {
	var s *access.Session
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+sessCols+` FROM access_sessions WHERE id=$1`, id)
		var e error
		s, e = scanSession(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		return e
	})
	return s, err
}

// sessColsQ is sessCols qualified for the joined listing query. Kept beside it:
// the two must scan into the same fields in the same order, and scanSession is
// shared, so a column added to one has to be added to the other.
const sessColsQ = `s.id, s.organization_id, s.user_id, s.device_id,
	` + sessDeviceNameSQL + `, COALESCE(s.device_type,''), COALESCE(s.device_address,''),
	s.protocol, s.status,
	s.granted_from, s.granted_until, COALESCE(host(s.client_ip),''), COALESCE(s.user_agent,''),
	COALESCE(s.gateway_node,''), s.started_at, s.ended_at, COALESCE(s.end_reason,''), s.created_at,
	COALESCE(s.watermark,''), s.last_activity_at`

// sessDeviceNameSQL is the device label for a listing row.
//
// The snapshot taken at connect wins; the joined device is only a fallback for
// rows written before that column existed. The other order would reintroduce the
// bug: deleting a device makes the join NULL, and preferring it would blank
// exactly the sessions the snapshot exists to protect.
const sessDeviceNameSQL = `COALESCE(NULLIF(s.device_name,''), d.name, '')`

// sessSortSQL maps a logical sort column to its ORDER BY expression. Lookup in a
// fixed map is what keeps a client-supplied sort name out of the statement text.
var sessSortSQL = map[string]string{
	"created":  "s.created_at",
	"started":  "COALESCE(s.started_at, s.created_at)",
	"duration": "COALESCE(s.ended_at, now()) - COALESCE(s.started_at, s.created_at)",
	"user":     "u.email",
	"device":   sessDeviceNameSQL,
	"protocol": "s.protocol",
	"status":   "s.status",
	"ip":       "s.client_ip",
}

// ListView returns one page of sessions with their user and device labels, and
// the total row count for the same filter.
//
// The joins are LEFT joins on purpose: a session outlives the user or device it
// references, and an audit trail that hides a session because someone deleted
// the device would be an audit trail with a hole in exactly the interesting spot.
func (r *AccessSessionRepo) ListView(ctx context.Context, sc access.Scope, f access.SessionFilter) ([]access.SessionView, int, error) {
	// The higher ceiling is here rather than on List because this is the endpoint
	// the console drains for a CSV of the filtered set; interactive pages ask for
	// at most a hundred rows.
	limit := normalizeLimitUpTo(f.Limit, maxExportLimit)
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	var out []access.SessionView
	total := 0
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		// COUNT(*) OVER() rides along with the page so the pager's total and its
		// rows come from one snapshot of the table.
		q := `SELECT ` + sessColsQ + `,
			COALESCE(u.email::text,''), COUNT(*) OVER()
			FROM access_sessions s
			LEFT JOIN users u ON u.id = s.user_id
			LEFT JOIN devices d ON d.id = s.device_id
			WHERE 1=1`
		args := []any{}
		i := 1
		if f.Status != "" {
			q += ` AND s.status = $` + strconv.Itoa(i)
			args = append(args, string(f.Status))
			i++
		}
		if f.UserID != nil {
			q += ` AND s.user_id = $` + strconv.Itoa(i)
			args = append(args, *f.UserID)
			i++
		}
		if f.DeviceID != nil {
			q += ` AND s.device_id = $` + strconv.Itoa(i)
			args = append(args, *f.DeviceID)
			i++
		}
		if s := strings.TrimSpace(f.Search); s != "" {
			p := strconv.Itoa(i)
			// host() so a search for "10.200" matches the address as displayed
			// rather than inet's textual form with its prefix length.
			// Searches the label the reviewer actually sees, snapshot included, so a
			// session whose device is gone is still findable by the name it had.
			cond := `(` + sessDeviceNameSQL + ` ILIKE $` + p + ` OR host(s.client_ip) ILIKE $` + p +
				` OR s.protocol ILIKE $` + p + ` OR s.status ILIKE $` + p
			if f.SearchEmail {
				cond += ` OR u.email::text ILIKE $` + p
			}
			cond += `)`
			q += ` AND ` + cond
			args = append(args, "%"+s+"%")
			i++
		}
		order := "s.created_at"
		if col, ok := sessSortSQL[f.SortBy]; ok {
			order = col
		}
		dir := " ASC"
		if f.SortDesc || f.SortBy == "" {
			dir = " DESC"
		}
		// s.id as the final key makes the order total: without it, rows sharing a
		// sort value can swap between pages and an operator sees one row twice
		// while never seeing another.
		q += ` ORDER BY ` + order + dir + `, s.id DESC LIMIT $` + strconv.Itoa(i) + ` OFFSET $` + strconv.Itoa(i+1)
		args = append(args, limit, offset)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v access.SessionView
			var proto, status string
			if err := rows.Scan(&v.ID, &v.OrganizationID, &v.UserID, &v.DeviceID,
				&v.DeviceName, &v.DeviceType, &v.DeviceAddress, &proto, &status,
				&v.GrantedFrom, &v.GrantedUntil, &v.ClientIP, &v.UserAgent,
				&v.GatewayNode, &v.StartedAt, &v.EndedAt, &v.EndReason, &v.CreatedAt,
				&v.Watermark, &v.LastActivityAt, &v.UserEmail, &total); err != nil {
				return err
			}
			v.Protocol = access.Protocol(proto)
			v.Status = access.Status(status)
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, total, err
}

// Stats returns live counters over every session in scope.
func (r *AccessSessionRepo) Stats(ctx context.Context, sc access.Scope) (access.SessionStats, error) {
	var st access.SessionStats
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		// One pass. 'expired' counts as ended: a session the reaper closed is over,
		// and a counter that says otherwise invites someone to go looking for a
		// live session that is not there.
		return tx.QueryRow(ctx, `
			SELECT COUNT(*),
			       COUNT(*) FILTER (WHERE status = 'active'),
			       COUNT(*) FILTER (WHERE status IN ('ended','expired')),
			       COUNT(DISTINCT device_id)
			FROM access_sessions`).Scan(&st.Total, &st.Active, &st.Ended, &st.Devices)
	})
	return st, err
}

// List returns sessions matching the filter.
func (r *AccessSessionRepo) List(ctx context.Context, sc access.Scope, f access.SessionFilter) ([]access.Session, error) {
	limit := normalizeLimit(f.Limit)
	var out []access.Session
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		q := `SELECT ` + sessCols + ` FROM access_sessions WHERE 1=1`
		args := []any{}
		i := 1
		if f.Status != "" {
			q += ` AND status = $` + strconv.Itoa(i)
			args = append(args, string(f.Status))
			i++
		}
		if f.UserID != nil {
			q += ` AND user_id = $` + strconv.Itoa(i)
			args = append(args, *f.UserID)
			i++
		}
		if f.DeviceID != nil {
			q += ` AND device_id = $` + strconv.Itoa(i)
			args = append(args, *f.DeviceID)
			i++
		}
		q += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(i)
		args = append(args, limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			s, e := scanSession(rows)
			if e != nil {
				return e
			}
			out = append(out, *s)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateStatus transitions a session and stamps timing fields.
func (r *AccessSessionRepo) UpdateStatus(ctx context.Context, sc access.Scope, id uuid.UUID, status access.Status, endReason string, at time.Time) error {
	return r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE access_sessions
			SET status=$2,
			    ended_at = CASE WHEN $2 IN ('ended','expired') THEN $4 ELSE ended_at END,
			    end_reason = CASE WHEN $3 <> '' THEN $3 ELSE end_reason END
			WHERE id=$1`, id, string(status), endReason, at)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return access.ErrNotFound
		}
		return nil
	})
}

// CountActive returns the number of active sessions in the tenant.
func (r *AccessSessionRepo) CountActive(ctx context.Context, sc access.Scope) (int, error) {
	var n int
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM access_sessions WHERE status='active'`).Scan(&n)
	})
	return n, err
}

// ExpireOverdue marks active sessions past their window as expired (system-wide).
// ExpireIdle ends active sessions whose device's idle timeout has elapsed since
// the last thing the operator did.
//
// The timeout is read from the device on every sweep rather than copied onto the
// session at connect time, so shortening a device's timeout takes effect on the
// sessions already open against it — which is the point of shortening it.
//
// COALESCE(last_activity_at, started_at, created_at): a session nobody has
// touched yet has no activity stamp, and must still age out from when it opened.
// Without the fallback, opening a session and walking away would leave it live
// until its window expired — precisely the case this exists to close.
//
// The $1::timestamptz cast is load-bearing: an uncast parameter lets Postgres
// resolve "$1 - make_interval(...)" as interval-minus-interval, and the sweep
// then dies on "timestamptz < interval" every tick.
func (r *AccessSessionRepo) ExpireIdle(ctx context.Context, now time.Time) ([]access.ExpiredSession, error) {
	var out []access.ExpiredSession
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		// Same again: an idle session died one idle-timeout after the last thing
		// that happened on it, which is a time the row already knows. The reaper is
		// the thing that notices, not the thing that decides when it ended.
		rows, err := tx.Query(ctx, `
			UPDATE access_sessions s
			SET status='expired',
			    ended_at = COALESCE(s.last_activity_at, s.started_at, s.created_at)
			               + make_interval(mins => d.idle_timeout_minutes),
			    end_reason='idle_timeout'
			FROM devices d
			WHERE s.device_id = d.id
			  AND s.status = 'active'
			  AND d.idle_timeout_minutes > 0
			  AND COALESCE(s.last_activity_at, s.started_at, s.created_at)
			      < $1::timestamptz - make_interval(mins => d.idle_timeout_minutes)
			RETURNING s.id, s.organization_id, s.protocol`, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e access.ExpiredSession
			if err := rows.Scan(&e.ID, &e.OrgID, &e.Protocol); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// TouchActivity stamps a session as used. Only active sessions are touched, so a
// late-arriving request cannot resurrect one the reaper just closed.
func (r *AccessSessionRepo) TouchActivity(ctx context.Context, id uuid.UUID, at time.Time) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE access_sessions SET last_activity_at=$2
			WHERE id=$1 AND status='active'`, id, at)
		return err
	})
}

func (r *AccessSessionRepo) ExpireOverdue(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		// ended_at is granted_until, NOT the moment the reaper noticed. Access was
		// authorized to exactly that instant and no further; stamping "now" records
		// however long the reaper happened to be late as time the session was open.
		// That is not a small error — the reaper only runs while the API does, so a
		// host that is off overnight adds the whole outage to every session that
		// lapsed during it. One session on this box reads as 21h when its window was
		// an hour and its last activity was four seconds in.
		ct, err := tx.Exec(ctx, `
			UPDATE access_sessions SET status='expired', ended_at=granted_until, end_reason='window_expired'
			WHERE status='active' AND granted_until IS NOT NULL AND granted_until < $1`, now)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}
