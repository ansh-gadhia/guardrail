package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// AccessSessionRepo implements access.SessionRepository.
type AccessSessionRepo struct{ db *DB }

// NewAccessSessionRepo constructs an AccessSessionRepo.
func NewAccessSessionRepo(db *DB) *AccessSessionRepo { return &AccessSessionRepo{db: db} }

const sessCols = `id, organization_id, user_id, device_id, protocol, status,
	granted_from, granted_until, COALESCE(host(client_ip),''), COALESCE(user_agent,''),
	COALESCE(gateway_node,''), started_at, ended_at, COALESCE(end_reason,''), created_at,
	COALESCE(watermark,'')`

func scanSession(row pgx.Row) (*access.Session, error) {
	var s access.Session
	var proto, status string
	if err := row.Scan(&s.ID, &s.OrganizationID, &s.UserID, &s.DeviceID, &proto, &status,
		&s.GrantedFrom, &s.GrantedUntil, &s.ClientIP, &s.UserAgent,
		&s.GatewayNode, &s.StartedAt, &s.EndedAt, &s.EndReason, &s.CreatedAt,
		// Empty for a session predating the column; WatermarkOr then falls back to
		// the session id, which is what those sessions were actually drawn with.
		&s.Watermark); err != nil {
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
				gateway_node, started_at, watermark)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::inet,$10,$11,$12,NULLIF($13,''))`,
			s.ID, s.OrganizationID, s.UserID, s.DeviceID, string(s.Protocol), string(s.Status),
			s.GrantedFrom, s.GrantedUntil, s.ClientIP, s.UserAgent,
			s.GatewayNode, s.StartedAt, s.Watermark)
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
		rows, err := tx.Query(ctx, `
			UPDATE access_sessions s
			SET status='expired', ended_at=$1, end_reason='idle_timeout'
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
		ct, err := tx.Exec(ctx, `
			UPDATE access_sessions SET status='expired', ended_at=$1, end_reason='window_expired'
			WHERE status='active' AND granted_until IS NOT NULL AND granted_until < $1`, now)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}
