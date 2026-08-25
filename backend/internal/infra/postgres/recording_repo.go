package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// RecordingRepo implements access.RecordingStore.
type RecordingRepo struct{ db *DB }

// NewRecordingRepo constructs a RecordingRepo.
func NewRecordingRepo(db *DB) *RecordingRepo { return &RecordingRepo{db: db} }

// Start creates a recording row for a session with a retention deadline.
func (r *RecordingRepo) Start(ctx context.Context, sc access.Scope, sessionID uuid.UUID, retention time.Duration) (*access.Recording, error) {
	rec := &access.Recording{ID: uuid.New(), SessionID: sessionID, Status: "recording"}
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		var retentionUntil *time.Time
		if retention > 0 {
			t := time.Now().Add(retention)
			retentionUntil = &t
		}
		return tx.QueryRow(ctx, `
			INSERT INTO recordings (id, organization_id, access_session_id, status, retention_until)
			VALUES ($1,$2,$3,'recording',$4) RETURNING started_at`,
			rec.ID, sc.OrganizationID, sessionID, retentionUntil).Scan(&rec.StartedAt)
	})
	return rec, err
}

// Finalize marks a recording finalized and computes its duration.
func (r *RecordingRepo) Finalize(ctx context.Context, sessionID uuid.UUID, at time.Time) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE recordings
			SET status='finalized', ended_at=$2,
			    duration_ms = EXTRACT(EPOCH FROM ($2 - started_at)) * 1000
			WHERE access_session_id=$1 AND status='recording'`, sessionID, at)
		return err
	})
}

// GetBySession returns the recording metadata for a session.
func (r *RecordingRepo) GetBySession(ctx context.Context, sc access.Scope, sessionID uuid.UUID) (*access.Recording, error) {
	var rec *access.Recording
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT id, access_session_id, status, started_at, ended_at, duration_ms
			FROM recordings WHERE access_session_id=$1`, sessionID)
		var v access.Recording
		if err := row.Scan(&v.ID, &v.SessionID, &v.Status, &v.StartedAt, &v.EndedAt, &v.DurationMS); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return access.ErrNotFound
			}
			return err
		}
		rec = &v
		return nil
	})
	return rec, err
}

// FindBySessionSystem resolves a recording without a tenant scope. The gateway
// needs this: it decides whether to capture during Establish, where there is a
// session but no acting user's scope to run under.
func (r *RecordingRepo) FindBySessionSystem(ctx context.Context, sessionID uuid.UUID) (*access.Recording, error) {
	var rec *access.Recording
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT id, access_session_id, status, started_at, ended_at, duration_ms
			FROM recordings WHERE access_session_id=$1`, sessionID)
		var v access.Recording
		if err := row.Scan(&v.ID, &v.SessionID, &v.Status, &v.StartedAt, &v.EndedAt, &v.DurationMS); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return access.ErrNotFound
			}
			return err
		}
		rec = &v
		return nil
	})
	return rec, err
}

// AddArtifact records one stored object belonging to a recording. Written by the
// gateway at teardown, so it is system-scoped like Finalize.
func (r *RecordingRepo) AddArtifact(ctx context.Context, recordingID uuid.UUID, a access.Artifact) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO recording_artifacts (id, recording_id, kind, object_key, size_bytes, content_type, checksum)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			a.ID, recordingID, a.Kind, a.ObjectKey, a.SizeBytes, a.ContentType, a.Checksum)
		return mapWriteErr(err)
	})
}

// GetArtifact returns a recording's artifact of the given kind. The join to
// recordings is what scopes it: recording_artifacts carries no organization_id
// of its own, so the parent's RLS is the tenant boundary.
func (r *RecordingRepo) GetArtifact(ctx context.Context, sc access.Scope, sessionID uuid.UUID, kind string) (*access.Artifact, error) {
	var art *access.Artifact
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT a.id, a.recording_id, a.kind, a.object_key, a.size_bytes, a.content_type,
				a.checksum, a.created_at
			FROM recording_artifacts a
			JOIN recordings r ON r.id = a.recording_id
			WHERE r.access_session_id=$1 AND a.kind=$2
			ORDER BY a.created_at DESC
			LIMIT 1`, sessionID, kind)
		var v access.Artifact
		if err := row.Scan(&v.ID, &v.RecordingID, &v.Kind, &v.ObjectKey, &v.SizeBytes,
			&v.ContentType, &v.Checksum, &v.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return access.ErrNotFound
			}
			return err
		}
		art = &v
		return nil
	})
	return art, err
}

// ListArtifacts returns every artifact belonging to a session's recording.
func (r *RecordingRepo) ListArtifacts(ctx context.Context, sc access.Scope, sessionID uuid.UUID) ([]access.Artifact, error) {
	var out []access.Artifact
	err := r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT a.id, a.recording_id, a.kind, a.object_key, a.size_bytes, a.content_type,
				a.checksum, a.created_at
			FROM recording_artifacts a
			JOIN recordings r ON r.id = a.recording_id
			WHERE r.access_session_id=$1
			ORDER BY a.created_at`, sessionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v access.Artifact
			if err := rows.Scan(&v.ID, &v.RecordingID, &v.Kind, &v.ObjectKey, &v.SizeBytes,
				&v.ContentType, &v.Checksum, &v.CreatedAt); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a session's recording and its artifact rows.
//
// Scoped like every other read here, so one tenant cannot delete another's
// evidence. Reports ErrNotFound when nothing matched rather than succeeding
// silently: "deleted" and "there was nothing there, possibly because it is not
// yours" must not look the same to the caller.
func (r *RecordingRepo) Delete(ctx context.Context, sc access.Scope, sessionID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, sc.OrganizationID, sc.IsSuperAdmin, func(tx pgx.Tx) error {
		// Artifacts first: they reference the recording.
		if _, err := tx.Exec(ctx, `
			DELETE FROM recording_artifacts a
			USING recordings r
			WHERE a.recording_id = r.id AND r.access_session_id=$1`, sessionID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM recordings WHERE access_session_id=$1`, sessionID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return access.ErrNotFound
		}
		return nil
	})
}

// DueForPurge lists recordings past their retention deadline, newest deadline
// first, across every tenant.
//
// System-scoped on purpose: the purge runs on a timer with no acting user and no
// organization, exactly like the session reaper. Scoping it to a tenant would
// mean the sweep only ever ran for whoever happened to be logged in.
//
// The limit bounds one pass. A deployment that has never purged may have years
// of recordings due at once, and deleting all of them inside a single
// transaction would hold locks for as long as that takes; the reaper simply
// comes back in thirty seconds for the next batch.
func (r *RecordingRepo) DueForPurge(ctx context.Context, now time.Time, limit int) ([]access.ExpiredRecording, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []access.ExpiredRecording
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT r.id, r.access_session_id, r.organization_id, r.retention_until,
			       COALESCE(array_agg(a.object_key) FILTER (WHERE a.object_key <> ''), '{}'),
			       COALESCE(array_agg(a.kind) FILTER (WHERE a.kind IS NOT NULL), '{}'),
			       COALESCE(SUM(a.size_bytes), 0)
			  FROM recordings r
			  LEFT JOIN recording_artifacts a ON a.recording_id = r.id
			 WHERE r.retention_until IS NOT NULL AND r.retention_until < $1
			 GROUP BY r.id, r.access_session_id, r.organization_id, r.retention_until
			 ORDER BY r.retention_until ASC
			 LIMIT $2`, now, limit)
		if err != nil {
			return fmt.Errorf("recordings: due for purge: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e access.ExpiredRecording
			if err := rows.Scan(&e.RecordingID, &e.SessionID, &e.OrgID, &e.RetainedTo,
				&e.ObjectKeys, &e.Kinds, &e.Bytes); err != nil {
				return fmt.Errorf("recordings: scan purge row: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// PurgeSystem drops an expired recording and its artifact rows. The caller frees
// the blobs first — a row deleted before its bytes leaves an object nothing
// points to, which is storage that is never reclaimed and never noticed.
func (r *RecordingRepo) PurgeSystem(ctx context.Context, recordingID uuid.UUID) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM recording_artifacts WHERE recording_id=$1`, recordingID); err != nil {
			return fmt.Errorf("recordings: purge artifacts: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM recordings WHERE id=$1`, recordingID); err != nil {
			return fmt.Errorf("recordings: purge: %w", err)
		}
		return nil
	})
}
