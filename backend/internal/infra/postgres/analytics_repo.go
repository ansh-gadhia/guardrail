package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/app/analytics"
)

// AnalyticsRepo implements the analytics read port. Every query runs inside a
// tenant-scoped transaction so RLS enforces isolation on the read model exactly
// as it does on writes.
type AnalyticsRepo struct{ db *DB }

// NewAnalyticsRepo constructs an AnalyticsRepo.
func NewAnalyticsRepo(db *DB) *AnalyticsRepo { return &AnalyticsRepo{db: db} }

func (r *AnalyticsRepo) scoped(ctx context.Context, s analytics.Scope, fn func(tx pgx.Tx) error) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, fn)
}

// Dashboard aggregates tenant-scoped counts and recent activity.
func (r *AnalyticsRepo) Dashboard(ctx context.Context, s analytics.Scope) (analytics.Summary, error) {
	var out analytics.Summary
	err := r.scoped(ctx, s, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM devices WHERE deleted_at IS NULL`).Scan(&out.Devices); err != nil {
			return fmt.Errorf("analytics: count devices: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM access_sessions WHERE status='active'`).Scan(&out.ActiveSessions); err != nil {
			return fmt.Errorf("analytics: count active sessions: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE deleted_at IS NULL`).Scan(&out.Users); err != nil {
			return fmt.Errorf("analytics: count users: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM audit_events
			  WHERE action='auth.login' AND result='failure' AND ts > now() - interval '24 hours'`).
			Scan(&out.FailedLogins24h); err != nil {
			return fmt.Errorf("analytics: count failed logins: %w", err)
		}

		// Top devices by session count.
		rows, err := tx.Query(ctx, `
			SELECT d.id::text, d.name, count(s.id) AS sessions
			  FROM devices d
			  LEFT JOIN access_sessions s ON s.device_id = d.id
			 WHERE d.deleted_at IS NULL
			 GROUP BY d.id, d.name
			 ORDER BY sessions DESC, d.name ASC
			 LIMIT 5`)
		if err != nil {
			return fmt.Errorf("analytics: top devices: %w", err)
		}
		for rows.Next() {
			var dc analytics.DeviceCount
			if err := rows.Scan(&dc.DeviceID, &dc.Name, &dc.Sessions); err != nil {
				rows.Close()
				return fmt.Errorf("analytics: scan top device: %w", err)
			}
			out.TopDevices = append(out.TopDevices, dc)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Recent activity feed.
		arows, err := tx.Query(ctx, `
			SELECT ts, COALESCE(actor_email,''), action, result
			  FROM audit_events
			 ORDER BY ts DESC, id DESC
			 LIMIT 10`)
		if err != nil {
			return fmt.Errorf("analytics: recent activity: %w", err)
		}
		for arows.Next() {
			var a analytics.ActivityItem
			if err := arows.Scan(&a.Timestamp, &a.Actor, &a.Action, &a.Result); err != nil {
				arows.Close()
				return fmt.Errorf("analytics: scan activity: %w", err)
			}
			out.RecentActivity = append(out.RecentActivity, a)
		}
		arows.Close()
		return arows.Err()
	})
	if out.TopDevices == nil {
		out.TopDevices = []analytics.DeviceCount{}
	}
	if out.RecentActivity == nil {
		out.RecentActivity = []analytics.ActivityItem{}
	}
	return out, err
}

// Search runs a case-insensitive prefix/substring match across entities.
func (r *AnalyticsRepo) Search(ctx context.Context, s analytics.Scope, q string, limit int) (analytics.SearchResults, error) {
	out := analytics.SearchResults{Users: []analytics.Hit{}, Devices: []analytics.Hit{}, Sessions: []analytics.Hit{}}
	pattern := "%" + strings.ToLower(q) + "%"
	err := r.scoped(ctx, s, func(tx pgx.Tx) error {
		urows, err := tx.Query(ctx, `
			SELECT id::text, email
			  FROM users
			 WHERE deleted_at IS NULL AND (lower(email) LIKE $1 OR lower(COALESCE(username,'')) LIKE $1)
			 ORDER BY email ASC LIMIT $2`, pattern, limit)
		if err != nil {
			return fmt.Errorf("analytics: search users: %w", err)
		}
		for urows.Next() {
			var h analytics.Hit
			if err := urows.Scan(&h.ID, &h.Label); err != nil {
				urows.Close()
				return err
			}
			out.Users = append(out.Users, h)
		}
		urows.Close()
		if err := urows.Err(); err != nil {
			return err
		}

		drows, err := tx.Query(ctx, `
			SELECT id::text, name || ' (' || host || ')'
			  FROM devices
			 WHERE deleted_at IS NULL AND (lower(name) LIKE $1 OR lower(host) LIKE $1 OR lower(vendor) LIKE $1)
			 ORDER BY name ASC LIMIT $2`, pattern, limit)
		if err != nil {
			return fmt.Errorf("analytics: search devices: %w", err)
		}
		for drows.Next() {
			var h analytics.Hit
			if err := drows.Scan(&h.ID, &h.Label); err != nil {
				drows.Close()
				return err
			}
			out.Devices = append(out.Devices, h)
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			return err
		}

		srows, err := tx.Query(ctx, `
			SELECT s.id::text, u.email || ' → ' || d.name || ' [' || s.status || ']'
			  FROM access_sessions s
			  JOIN users u ON u.id = s.user_id
			  JOIN devices d ON d.id = s.device_id
			 WHERE lower(u.email) LIKE $1 OR lower(d.name) LIKE $1
			 ORDER BY s.created_at DESC LIMIT $2`, pattern, limit)
		if err != nil {
			return fmt.Errorf("analytics: search sessions: %w", err)
		}
		for srows.Next() {
			var h analytics.Hit
			if err := srows.Scan(&h.ID, &h.Label); err != nil {
				srows.Close()
				return err
			}
			out.Sessions = append(out.Sessions, h)
		}
		srows.Close()
		return srows.Err()
	})
	return out, err
}

// ListAudit returns audit rows matching the filter, newest first.
func (r *AnalyticsRepo) ListAudit(ctx context.Context, s analytics.Scope, f analytics.AuditFilter) ([]analytics.AuditRow, error) {
	limit := f.Limit
	if limit <= 0 || limit > 10000 {
		limit = 200
	}

	var where []string
	var args []any
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Action != "" {
		add("action ILIKE '%%' || $%d || '%%'", f.Action)
	}
	if f.Actor != "" {
		add("actor_email ILIKE '%%' || $%d || '%%'", f.Actor)
	}
	if f.Result != "" {
		add("result = $%d", f.Result)
	}
	if f.TargetType != "" {
		add("target_type = $%d", f.TargetType)
	}
	if f.TargetID != "" {
		add("target_id = $%d", f.TargetID)
	}
	if f.From != nil {
		add("ts >= $%d", *f.From)
	}
	if f.To != nil {
		add("ts <= $%d", *f.To)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT ts, COALESCE(actor_email,''), action, category,
		       COALESCE(target_type,''), COALESCE(target_id,''),
		       COALESCE(host(ip),''), COALESCE(user_agent,''), result, detail
		  FROM audit_events
		  %s
		 ORDER BY ts DESC, id DESC
		 LIMIT $%d`, whereSQL, len(args))

	out := []analytics.AuditRow{}
	err := r.scoped(ctx, s, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("analytics: list audit: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a analytics.AuditRow
			var detail []byte
			if err := rows.Scan(&a.Timestamp, &a.ActorEmail, &a.Action, &a.Category,
				&a.TargetType, &a.TargetID, &a.IP, &a.UserAgent, &a.Result, &detail); err != nil {
				return fmt.Errorf("analytics: scan audit: %w", err)
			}
			if len(detail) > 0 {
				_ = json.Unmarshal(detail, &a.Detail) // best-effort; malformed detail simply omitted
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
