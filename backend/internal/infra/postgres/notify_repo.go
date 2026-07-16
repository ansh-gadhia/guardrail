package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/notify"
)

// ChannelRepo implements notify.ChannelRepository.
type ChannelRepo struct{ db *DB }

// NewChannelRepo constructs a ChannelRepo.
func NewChannelRepo(db *DB) *ChannelRepo { return &ChannelRepo{db: db} }

func scanChannel(row pgx.Row) (*notify.Channel, error) {
	var c notify.Channel
	var typ string
	var cfg []byte
	if err := row.Scan(&c.ID, &c.OrganizationID, &c.Name, &typ, &cfg, &c.Events, &c.Enabled); err != nil {
		return nil, err
	}
	c.Type = notify.ChannelType(typ)
	if len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &c.Config)
	}
	return &c, nil
}

const channelCols = `id, organization_id, name, type, config, events, enabled`

// Create inserts a notification channel.
func (r *ChannelRepo) Create(ctx context.Context, s notify.Scope, c *notify.Channel) error {
	cfg, _ := json.Marshal(c.Config)
	events := c.Events
	if events == nil {
		events = []string{}
	}
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_channels
			(id, organization_id, name, type, config, events, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			c.ID, c.OrganizationID, c.Name, string(c.Type), cfg, events, c.Enabled)
		return mapWriteErr(err)
	})
}

// List returns channels in scope.
func (r *ChannelRepo) List(ctx context.Context, s notify.Scope) ([]notify.Channel, error) {
	var out []notify.Channel
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+channelCols+` FROM notification_channels ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ch, e := scanChannel(rows)
			if e != nil {
				return e
			}
			out = append(out, *ch)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a channel.
func (r *ChannelRepo) Delete(ctx context.Context, s notify.Scope, id uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return notify.ErrNotFound
		}
		return nil
	})
}

// ListForOrg returns enabled channels for an org (system-scoped fan-out).
func (r *ChannelRepo) ListForOrg(ctx context.Context, orgID uuid.UUID) ([]notify.Channel, error) {
	var out []notify.Channel
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+channelCols+`
			FROM notification_channels WHERE organization_id=$1 AND enabled=true`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ch, e := scanChannel(rows)
			if e != nil {
				return e
			}
			out = append(out, *ch)
		}
		return rows.Err()
	})
	return out, err
}

// OutboxRepo implements notify.Outbox.
type OutboxRepo struct{ db *DB }

// NewOutboxRepo constructs an OutboxRepo.
func NewOutboxRepo(db *DB) *OutboxRepo { return &OutboxRepo{db: db} }

// Enqueue persists a pending notification (system-scoped: written by fan-out).
func (r *OutboxRepo) Enqueue(ctx context.Context, n *notify.Notification) error {
	payload, _ := json.Marshal(n.Payload)
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notifications
			(id, organization_id, channel_id, event, payload, status)
			VALUES ($1,$2,$3,$4,$5,'pending')`,
			n.ID, n.OrganizationID, n.ChannelID, n.Event, payload)
		return err
	})
}

// ListPending returns queued notifications for the dispatcher.
func (r *OutboxRepo) ListPending(ctx context.Context, limit int) ([]notify.Notification, error) {
	limit = normalizeLimit(limit)
	var out []notify.Notification
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, channel_id, event, payload, attempts
			FROM notifications WHERE status='pending' ORDER BY created_at LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n notify.Notification
			var payload []byte
			if err := rows.Scan(&n.ID, &n.OrganizationID, &n.ChannelID, &n.Event, &payload, &n.Attempts); err != nil {
				return err
			}
			if len(payload) > 0 {
				_ = json.Unmarshal(payload, &n.Payload)
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// MarkSent marks a notification delivered.
func (r *OutboxRepo) MarkSent(ctx context.Context, id uuid.UUID, at time.Time) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notifications SET status='sent', sent_at=$2, attempts=attempts+1 WHERE id=$1`, id, at)
		return err
	})
}

// MarkFailed records a delivery failure (kept pending for retry up to a cap set
// by the dispatcher).
func (r *OutboxRepo) MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	return r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notifications
			SET attempts=attempts+1, last_error=$2,
			    status = CASE WHEN attempts+1 >= 5 THEN 'failed' ELSE 'pending' END
			WHERE id=$1`, id, errMsg)
		return err
	})
}
