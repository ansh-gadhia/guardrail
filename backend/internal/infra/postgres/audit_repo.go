package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"

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
	// Never persist a zero timestamp. Several callers (the access, vault and notify
	// services) build the event without setting Timestamp, and the column's
	// DEFAULT now() does NOT apply because an explicit value — the Go zero time — is
	// passed, so those rows landed as 0001-01-01 and rendered as "739814d ago".
	// Default it here, before the hash below is computed over it, so the timestamp
	// is both stored and chained correctly. Callers that set Timestamp themselves
	// (the IAM auth path) keep their own value.
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Truncated to what the column can hold. timestamptz keeps microseconds and Go
	// keeps nanoseconds, so hashing the un-truncated value produced a hash that
	// could never be recomputed from the stored row — every honest event failed
	// verification, which is why nothing had ever verified one.
	e.Timestamp = e.Timestamp.UTC().Truncate(time.Microsecond)
	// Same reasoning for the address: Postgres canonicalises inet, so the hash has
	// to be taken over the canonical form rather than over whatever was passed in.
	e.IP = canonicalIP(e.IP)

	return r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		// Serialize per-org chain writers.
		lockKey := "system"
		if e.OrganizationID != nil {
			lockKey = e.OrganizationID.String()
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, lockKey); err != nil {
			return fmt.Errorf("audit: advisory lock: %w", err)
		}

		// Fetch the tail hash of this org's chain — the LAST-INSERTED event, by
		// seq. It used to be the latest-DATED event, which is a different row
		// whenever two events are written out of timestamp order: both then linked
		// to the same predecessor and the chain forked. A forked chain establishes
		// nothing, because a spliced-in row is indistinguishable from a branch.
		var prev []byte
		var row pgx.Row
		if e.OrganizationID != nil {
			row = tx.QueryRow(ctx, `SELECT hash FROM audit_events
				WHERE organization_id=$1 ORDER BY seq DESC LIMIT 1`, *e.OrganizationID)
		} else {
			row = tx.QueryRow(ctx, `SELECT hash FROM audit_events
				WHERE organization_id IS NULL ORDER BY seq DESC LIMIT 1`)
		}
		if err := row.Scan(&prev); err != nil && err != pgx.ErrNoRows {
			return fmt.Errorf("audit: read prev hash: %w", err)
		}

		detail, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("audit: marshal detail: %w", err)
		}
		// Hashed over the canonical form, not the bytes Go happened to produce:
		// jsonb re-orders object keys and drops whitespace, so the raw encoding is
		// not what comes back out.
		hash := chainHash(prev, e, canonicalJSON(detail))

		_, err = tx.Exec(ctx, `
			INSERT INTO audit_events (id, organization_id, ts, actor_id, actor_email,
				action, category, target_type, target_id, session_id, ip, user_agent,
				result, detail, prev_hash, hash, hash_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,'')::inet,$12,$13,$14,$15,$16,$17)`,
			e.ID, e.OrganizationID, e.Timestamp, e.ActorID, e.ActorEmail,
			e.Action, string(e.Category), e.TargetType, e.TargetID, e.SessionID,
			e.IP, e.UserAgent, string(e.Result), detail, prev, hash, chainHashVersion)
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

// chainHashVersion marks rows whose hash was taken over values that survive the
// database round trip, and can therefore be recomputed. Rows written before this
// existed carry version 1 and are reported as unverifiable — not as altered.
const chainHashVersion = 2

// canonicalJSON re-encodes a JSON document so the same value always yields the
// same bytes on both sides of the database.
//
// Go's encoder sorts object keys lexicographically; jsonb sorts them by length
// and then by bytes, and renders numbers and spacing its own way. Hashing either
// side's raw bytes therefore fails against the other. Both the writer and the
// verifier run everything through here first.
func canonicalJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay as their literal text: a float64 round trip would quietly
	// re-render a large integer.
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Go escapes <, > and & by default and Postgres does not, so a detail value
	// containing any of them would not survive.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// canonicalIP renders an address the way Postgres will hand it back.
func canonicalIP(raw string) string {
	if raw == "" {
		return ""
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return raw
	}
	return addr.Unmap().String()
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

// VerifyChain recomputes an organization's hash chain and reports the first row
// that does not match.
//
// The chain shipped in the first release and nothing ever read it, which made
// tamper-evidence a claim rather than a demonstration. An append-only table with
// no UPDATE or DELETE grant stops the application from rewriting history; it does
// not stop somebody with database access, and the whole point of a hash chain is
// that such a rewrite is detectable. It is only detectable if something detects
// it.
//
// Two checks, in insertion order (seq, which is the order the chain was built
// in — see migration 0032):
//
//   - the LINK: each event must name the hash of the event before it, which is
//     what makes an insertion, a deletion or a reordering visible;
//   - the CONTENTS: recomputing an event's hash from its own stored fields must
//     reproduce the hash it carries, which is what makes an edit visible.
//
// Events written before hash_version 2 are counted and skipped rather than
// failed. Their hashes were taken over Go values that the database rounded and
// re-ordered on the way in, so they cannot be recomputed from what was stored —
// through no fault of the rows themselves. Reporting them as altered would cry
// wolf on every existing deployment, and the log is append-only by design: there
// is nothing legitimate to rewrite them with.
//
// System-scoped and read-only.
func (r *AuditRepo) VerifyChain(ctx context.Context, orgID *uuid.UUID, limit int) (*audit.ChainReport, error) {
	if limit <= 0 || limit > maxChainWalk {
		limit = defaultChainWalk
	}
	rep := &audit.ChainReport{OK: true}

	err := r.db.withSystemScope(ctx, func(tx pgx.Tx) error {
		q := `SELECT id, organization_id, ts, actor_id, actor_email, action, category,
		             COALESCE(target_type,''), COALESCE(target_id,''), session_id,
		             COALESCE(host(ip),''), COALESCE(user_agent,''), result, detail,
		             COALESCE(prev_hash,''::bytea), hash, hash_version
		        FROM audit_events`
		args := []any{}
		if orgID != nil {
			args = append(args, *orgID)
			q += ` WHERE organization_id=$1`
		} else {
			q += ` WHERE organization_id IS NULL`
		}
		args = append(args, limit+1)
		q += ` ORDER BY seq ASC LIMIT $` + strconv.Itoa(len(args))

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("audit: verify: %w", err)
		}
		defer rows.Close()

		var prev []byte
		seen := 0
		havePrev := false
		for rows.Next() {
			if seen == limit {
				// One row was read past the cap purely to learn that there is more.
				rep.Truncated = true
				break
			}
			var e audit.Event
			var detail, storedPrev, storedHash []byte
			var result string
			var version int16
			if err := rows.Scan(&e.ID, &e.OrganizationID, &e.Timestamp, &e.ActorID, &e.ActorEmail,
				&e.Action, &e.Category, &e.TargetType, &e.TargetID, &e.SessionID,
				&e.IP, &e.UserAgent, &result, &detail, &storedPrev, &storedHash, &version); err != nil {
				return fmt.Errorf("audit: verify scan: %w", err)
			}
			e.Result = audit.Result(result)
			seen++

			if version < chainHashVersion {
				// Unverifiable, not wrong. Its hash still anchors the events that
				// follow it, so the link is carried forward.
				rep.Unverifiable++
				prev, havePrev = storedHash, true
				continue
			}

			if havePrev && !bytes.Equal(storedPrev, prev) {
				rep.Fail(e, "this event does not follow the one before it: an event has been inserted, removed or reordered")
				return nil
			}
			if want := chainHash(storedPrev, e, canonicalJSON(detail)); !bytes.Equal(want, storedHash) {
				rep.Fail(e, "this event's contents no longer match its hash: a stored field has been altered")
				return nil
			}

			// Counted only once it has passed. Checked is what the report claims to
			// have proved, and a row that failed both checks was not proved.
			rep.Checked++
			if !e.Timestamp.IsZero() {
				if rep.From.IsZero() {
					rep.From = e.Timestamp
				}
				rep.To = e.Timestamp
			}
			prev, havePrev = storedHash, true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// How much of a chain one pass walks.
const (
	defaultChainWalk = 25_000
	maxChainWalk     = 200_000
)
