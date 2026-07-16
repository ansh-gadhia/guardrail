package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// SessionEventRepo implements access.EventRecorder — the per-session timeline
// used for playback and audit.
type SessionEventRepo struct{ db *DB }

// NewSessionEventRepo constructs a SessionEventRepo.
func NewSessionEventRepo(db *DB) *SessionEventRepo { return &SessionEventRepo{db: db} }

// RecordEvent appends a timeline event (system-scoped: written by the gateway
// during an active session).
func (r *SessionEventRepo) RecordEvent(ctx context.Context, sessionID uuid.UUID, kind string, data map[string]any) error {
	payload, _ := json.Marshal(data)
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO session_events (access_session_id, kind, data)
			VALUES ($1,$2,$3)`, sessionID, kind, payload)
		return err
	})
}

// ListEvents returns a session's timeline, tenant-scoped via the parent session.
func (r *SessionEventRepo) ListEvents(ctx context.Context, sc access.Scope, sessionID uuid.UUID, limit int) ([]access.Event, error) {
	limit = normalizeLimit(limit)
	var out []access.Event
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		// Join to access_sessions so RLS on that table enforces tenant scoping.
		rows, err := tx.Query(ctx, `
			SELECT e.ts, e.kind, e.data
			FROM session_events e
			JOIN access_sessions s ON s.id = e.access_session_id
			WHERE e.access_session_id = $1
			ORDER BY e.ts ASC LIMIT $2`, sessionID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev access.Event
			var data []byte
			if err := rows.Scan(&ev.Timestamp, &ev.Kind, &data); err != nil {
				return err
			}
			if len(data) > 0 {
				_ = json.Unmarshal(data, &ev.Data)
			}
			out = append(out, ev)
		}
		return rows.Err()
	})
	return out, err
}
