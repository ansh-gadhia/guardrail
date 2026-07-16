package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/guardrail/guardrail/internal/domain/audit"
)

// AuditRepo implements audit.Recorder with a per-organization hash chain:
//
//	hash = SHA256(prev_hash || canonical(event))
//
// A transaction-scoped advisory lock per org serializes concurrent inserts so
// the chain never forks. The application DB role has no UPDATE/DELETE grant on
// audit_events, so the chain is append-only and tamper-evident.
type AuditRepo struct{ db *DB }

// NewAuditRepo constructs an AuditRepo.
func NewAuditRepo(db *DB) *AuditRepo { return &AuditRepo{db: db} }

// Record appends an event, linking it to the previous event for its org.
func (r *AuditRepo) Record(ctx context.Context, e audit.Event) error {
	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		// Serialize per-org chain writers.
		lockKey := "system"
		if e.OrganizationID != nil {
			lockKey = e.OrganizationID.String()
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, lockKey); err != nil {
			return fmt.Errorf("audit: advisory lock: %w", err)
		}

		// Fetch the tail hash of this org's chain.
		var prev []byte
		var row pgx.Row
		if e.OrganizationID != nil {
			row = tx.QueryRow(ctx, `SELECT hash FROM audit_events
				WHERE organization_id=$1 ORDER BY ts DESC, id DESC LIMIT 1`, *e.OrganizationID)
		} else {
			row = tx.QueryRow(ctx, `SELECT hash FROM audit_events
				WHERE organization_id IS NULL ORDER BY ts DESC, id DESC LIMIT 1`)
		}
		if err := row.Scan(&prev); err != nil && err != pgx.ErrNoRows {
			return fmt.Errorf("audit: read prev hash: %w", err)
		}

		detail, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("audit: marshal detail: %w", err)
		}
		hash := chainHash(prev, e, detail)

		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events (id, organization_id, ts, actor_id, actor_email,
				action, category, target_type, target_id, session_id, ip, user_agent,
				result, detail, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,'')::inet,$12,$13,$14,$15,$16)`,
			e.ID, e.OrganizationID, e.Timestamp, e.ActorID, e.ActorEmail,
			e.Action, string(e.Category), e.TargetType, e.TargetID, e.SessionID,
			e.IP, e.UserAgent, string(e.Result), detail, prev, hash)
		if err != nil {
			return fmt.Errorf("audit: insert: %w", err)
		}
		return nil
	})
}

// chainHash computes the tamper-evident hash over the previous hash and a
// canonical encoding of the event's immutable fields.
func chainHash(prev []byte, e audit.Event, detail []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	canonical := struct {
		Org        string `json:"org"`
		TS         string `json:"ts"`
		Actor      string `json:"actor"`
		ActorEmail string `json:"actor_email"`
		Action     string `json:"action"`
		Category   string `json:"category"`
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Session    string `json:"session"`
		IP         string `json:"ip"`
		UA         string `json:"ua"`
		Result     string `json:"result"`
	}{
		Org:        ptrString(orgToStr(e)),
		TS:         e.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Actor:      actorToStr(e),
		ActorEmail: e.ActorEmail,
		Action:     e.Action,
		Category:   string(e.Category),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Session:    sessionToStr(e),
		IP:         e.IP,
		UA:         e.UserAgent,
		Result:     string(e.Result),
	}
	b, _ := json.Marshal(canonical)
	h.Write(b)
	h.Write(detail)
	return h.Sum(nil)
}

func orgToStr(e audit.Event) *string {
	if e.OrganizationID == nil {
		return nil
	}
	s := e.OrganizationID.String()
	return &s
}
func actorToStr(e audit.Event) string {
	if e.ActorID == nil {
		return ""
	}
	return e.ActorID.String()
}
func sessionToStr(e audit.Event) string {
	if e.SessionID == nil {
		return ""
	}
	return e.SessionID.String()
}
func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
