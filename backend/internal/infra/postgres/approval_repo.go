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

// RequestRepo implements access.RequestRepository.
type RequestRepo struct{ db *DB }

// NewRequestRepo constructs a RequestRepo.
func NewRequestRepo(db *DB) *RequestRepo { return &RequestRepo{db: db} }

const requestCols = `r.id, r.organization_id, r.user_id, r.device_id, r.status, r.reason,
	r.requested_minutes, r.granted_minutes, r.grant_scope, r.min_approvals, r.requester_level,
	r.is_emergency, r.reviewed_by, r.reviewed_at, r.review_note, r.escalated_level,
	r.session_id, r.expires_at, r.created_at, r.updated_at`

const requestFrom = ` FROM access_requests r`

func scanRequest(row pgx.Row) (*access.Request, error) {
	var q access.Request
	var status string
	var scope *string
	if err := row.Scan(&q.ID, &q.OrganizationID, &q.UserID, &q.DeviceID, &status, &q.Reason,
		&q.RequestedMinutes, &q.GrantedMinutes, &scope, &q.MinApprovals, &q.RequesterLevel,
		&q.IsEmergency, &q.ReviewedBy, &q.ReviewedAt, &q.ReviewNote, &q.EscalatedLevel,
		&q.SessionID, &q.ExpiresAt, &q.CreatedAt, &q.UpdatedAt); err != nil {
		return nil, err
	}
	q.Status = access.RequestStatus(status)
	if scope != nil {
		gs := access.GrantScope(*scope)
		q.GrantScope = &gs
	}
	return &q, nil
}

// Create inserts a request.
func (r *RequestRepo) Create(ctx context.Context, s access.Scope, q *access.Request) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO access_requests (id, organization_id, user_id, device_id, status, reason,
				requested_minutes, min_approvals, requester_level, is_emergency, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			RETURNING created_at, updated_at`,
			q.ID, q.OrganizationID, q.UserID, q.DeviceID, string(q.Status), q.Reason,
			q.RequestedMinutes, q.MinApprovals, q.RequesterLevel, q.IsEmergency, q.ExpiresAt).
			Scan(&q.CreatedAt, &q.UpdatedAt)
	})
}

// GetByID loads a request with its decisions.
func (r *RequestRepo) GetByID(ctx context.Context, s access.Scope, id uuid.UUID) (*access.Request, error) {
	var q *access.Request
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+requestCols+requestFrom+` WHERE r.id=$1`, id)
		var e error
		q, e = scanRequest(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		if e != nil {
			return e
		}
		if e = loadProjections(ctx, tx, q); e != nil {
			return e
		}
		return loadDecisions(ctx, tx, q)
	})
	return q, err
}

// loadProjections fills the display fields a console row needs.
func loadProjections(ctx context.Context, tx pgx.Tx, q *access.Request) error {
	return tx.QueryRow(ctx, `
		SELECT COALESCE(u.email::text, ''), COALESCE(d.name, '')
		FROM access_requests r
		LEFT JOIN users u ON u.id = r.user_id
		LEFT JOIN devices d ON d.id = r.device_id
		WHERE r.id = $1`, q.ID).Scan(&q.RequesterEmail, &q.DeviceName)
}

func loadDecisions(ctx context.Context, tx pgx.Tx, q *access.Request) error {
	rows, err := tx.Query(ctx, `
		SELECT d.request_id, d.decided_by, d.decision, d.note, d.decided_at,
			COALESCE(u.email::text, '')
		FROM access_request_decisions d
		LEFT JOIN users u ON u.id = d.decided_by
		WHERE d.request_id=$1 ORDER BY d.decided_at`, q.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	q.Decisions = nil
	for rows.Next() {
		var d access.Decision
		if e := rows.Scan(&d.RequestID, &d.DecidedBy, &d.Decision, &d.Note, &d.DecidedAt,
			&d.DecidedByEmail); e != nil {
			return e
		}
		q.Decisions = append(q.Decisions, d)
	}
	return rows.Err()
}

// List returns requests matching a filter, newest first.
func (r *RequestRepo) List(ctx context.Context, s access.Scope, f access.RequestFilter) ([]access.Request, error) {
	limit := normalizeLimit(f.Limit)
	var out []access.Request
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		q := `SELECT ` + requestCols + `, COALESCE(u.email::text, ''), COALESCE(d.name, '')` +
			requestFrom + ` LEFT JOIN users u ON u.id = r.user_id LEFT JOIN devices d ON d.id = r.device_id WHERE 1=1`
		args := []any{}
		if f.Status != "" {
			args = append(args, string(f.Status))
			q += ` AND r.status = $` + strconv.Itoa(len(args))
		}
		if f.PendingOnly {
			q += ` AND r.status = 'pending'`
		}
		if f.UnreviewedEmergency {
			q += ` AND r.is_emergency AND r.reviewed_at IS NULL`
		}
		if f.UserID != nil {
			args = append(args, *f.UserID)
			q += ` AND r.user_id = $` + strconv.Itoa(len(args))
		}
		if f.DeviceID != nil {
			args = append(args, *f.DeviceID)
			q += ` AND r.device_id = $` + strconv.Itoa(len(args))
		}
		args = append(args, limit)
		q += ` ORDER BY r.created_at DESC LIMIT $` + strconv.Itoa(len(args))

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		ids := []uuid.UUID{}
		for rows.Next() {
			var req access.Request
			var status string
			var scope *string
			if e := rows.Scan(&req.ID, &req.OrganizationID, &req.UserID, &req.DeviceID, &status, &req.Reason,
				&req.RequestedMinutes, &req.GrantedMinutes, &scope, &req.MinApprovals, &req.RequesterLevel,
				&req.IsEmergency, &req.ReviewedBy, &req.ReviewedAt, &req.ReviewNote, &req.EscalatedLevel,
				&req.SessionID, &req.ExpiresAt, &req.CreatedAt, &req.UpdatedAt,
				&req.RequesterEmail, &req.DeviceName); e != nil {
				return e
			}
			req.Status = access.RequestStatus(status)
			if scope != nil {
				gs := access.GrantScope(*scope)
				req.GrantScope = &gs
			}
			out = append(out, req)
			ids = append(ids, req.ID)
		}
		if e := rows.Err(); e != nil {
			return e
		}
		return attachDecisions(ctx, tx, out, ids)
	})
	return out, err
}

// attachDecisions loads every listed request's votes in one query rather than
// one per row: the approval queue is a list, and N+1 on the queue view is how a
// screen that should be instant becomes a spinner.
func attachDecisions(ctx context.Context, tx pgx.Tx, reqs []access.Request, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT d.request_id, d.decided_by, d.decision, d.note, d.decided_at,
			COALESCE(u.email::text, '')
		FROM access_request_decisions d
		LEFT JOIN users u ON u.id = d.decided_by
		WHERE d.request_id = ANY($1) ORDER BY d.decided_at`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := make(map[uuid.UUID][]access.Decision, len(ids))
	for rows.Next() {
		var d access.Decision
		if e := rows.Scan(&d.RequestID, &d.DecidedBy, &d.Decision, &d.Note, &d.DecidedAt,
			&d.DecidedByEmail); e != nil {
			return e
		}
		byID[d.RequestID] = append(byID[d.RequestID], d)
	}
	if e := rows.Err(); e != nil {
		return e
	}
	for i := range reqs {
		reqs[i].Decisions = byID[reqs[i].ID]
	}
	return nil
}

// AddDecision records one vote and settles the request in the same transaction.
//
// The row is locked FOR UPDATE first. Two approvers pressing Approve at the same
// moment would otherwise both read "one more needed", both insert, and both
// leave the status pending — a request with two approvals that never opens.
func (r *RequestRepo) AddDecision(ctx context.Context, s access.Scope, requestID, deciderID uuid.UUID,
	d access.Decision, approverLevel int, isSuperAdmin bool) (*access.Request, error) {
	var out *access.Request
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+requestCols+requestFrom+` WHERE r.id=$1 FOR UPDATE`, requestID)
		q, e := scanRequest(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		if e != nil {
			return e
		}
		if q.Status != access.RequestPending {
			return access.ErrRequestNotPending
		}
		// Rank is checked here, inside the transaction, against the level the
		// request was made at. Strictly greater — which is also why nobody can
		// approve their own request: you never outrank yourself.
		if !isSuperAdmin && approverLevel <= q.RequesterLevel {
			return access.ErrCannotDecide
		}
		if e = loadDecisions(ctx, tx, q); e != nil {
			return e
		}
		if q.DecidedBy(deciderID) {
			return access.ErrAlreadyDecided
		}

		if _, e = tx.Exec(ctx, `
			INSERT INTO access_request_decisions (request_id, decided_by, decision, note)
			VALUES ($1,$2,$3,$4)`, requestID, deciderID, d.Decision, d.Note); e != nil {
			return mapWriteErr(e)
		}
		q.Decisions = append(q.Decisions, access.Decision{
			RequestID: requestID, DecidedBy: deciderID, Decision: d.Decision, Note: d.Note,
		})

		// One denial settles it. The two-person rule raises the bar for granting
		// access, never for refusing it.
		switch {
		case d.Decision == access.DecisionDeny:
			q.Status = access.RequestDenied
		case q.Satisfied():
			q.Status = access.RequestApproved
		}

		var scope *string
		if q.GrantScope != nil {
			v := string(*q.GrantScope)
			scope = &v
		}
		if _, e = tx.Exec(ctx, `
			UPDATE access_requests SET status=$2, granted_minutes=$3, grant_scope=$4 WHERE id=$1`,
			requestID, string(q.Status), q.GrantedMinutes, scope); e != nil {
			return e
		}
		if e = loadProjections(ctx, tx, q); e != nil {
			return e
		}
		out = q
		return nil
	})
	return out, err
}

// SetOutcome records the window and scope an approver settled on, before the
// vote is cast. Kept separate so AddDecision stays a pure vote.
func (r *RequestRepo) SetOutcome(ctx context.Context, s access.Scope, requestID uuid.UUID,
	grantedMinutes *int, scope *access.GrantScope) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		var sc *string
		if scope != nil {
			v := string(*scope)
			sc = &v
		}
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests SET granted_minutes=COALESCE($2, granted_minutes),
				grant_scope=COALESCE($3, grant_scope)
			WHERE id=$1 AND status='pending'`, requestID, grantedMinutes, sc)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return access.ErrRequestNotPending
		}
		return nil
	})
}

// Redeem attaches a session to an approved request, exactly once.
//
// The session_id IS NULL predicate is what makes "allow once" mean once: two
// tabs racing the same approval both pass the application check, and only one
// updates a row.
func (r *RequestRepo) Redeem(ctx context.Context, s access.Scope, requestID, sessionID uuid.UUID, now time.Time) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests SET session_id=$2
			WHERE id=$1 AND status='approved' AND session_id IS NULL AND expires_at > $3`,
			requestID, sessionID, now)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return access.ErrRequestNotApproved
		}
		return nil
	})
}

// Cancel withdraws a pending request raised by this user.
func (r *RequestRepo) Cancel(ctx context.Context, s access.Scope, requestID, userID uuid.UUID) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests SET status='cancelled'
			WHERE id=$1 AND user_id=$2 AND status='pending'`, requestID, userID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return access.ErrRequestNotPending
		}
		return nil
	})
}

// PendingFor returns this user's live request for a device: one still awaiting a
// decision, or one already approved and not yet redeemed.
func (r *RequestRepo) PendingFor(ctx context.Context, s access.Scope, userID, deviceID uuid.UUID, now time.Time) (*access.Request, error) {
	var q *access.Request
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+requestCols+requestFrom+`
			WHERE r.user_id=$1 AND r.device_id=$2 AND r.expires_at > $3
			  AND (r.status='pending' OR (r.status='approved' AND r.session_id IS NULL))
			ORDER BY r.created_at DESC LIMIT 1`, userID, deviceID, now)
		var e error
		q, e = scanRequest(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		if e != nil {
			return e
		}
		if e = loadProjections(ctx, tx, q); e != nil {
			return e
		}
		return loadDecisions(ctx, tx, q)
	})
	return q, err
}

// CountPending counts a user's outstanding requests.
func (r *RequestRepo) CountPending(ctx context.Context, s access.Scope, userID uuid.UUID) (int, error) {
	var n int
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM access_requests WHERE user_id=$1 AND status='pending'`, userID).Scan(&n)
	})
	return n, err
}

// Escalate raises requests that have gone unanswered past their deadline to the
// next rank and gives them a fresh window, returning how many moved.
//
// Escalating rather than expiring immediately is the difference between a
// request that finds somebody and one that quietly dies because the first
// person to see it was on leave.
func (r *RequestRepo) Escalate(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests
			SET escalated_level = COALESCE(escalated_level, requester_level) + 1,
				expires_at = $1
			WHERE status='pending' AND escalated_level IS NULL AND expires_at <= $2`,
			now.Add(access.DefaultRequestTTL), now)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// ExpireOverdue closes out requests nobody answered in time.
func (r *RequestRepo) ExpireOverdue(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := r.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		// Approved-but-unredeemed expires too. An approval that stays redeemable
		// indefinitely is a standing grant nobody chose to write down.
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests SET status='expired'
			WHERE expires_at <= $1
			  AND (status='pending' OR (status='approved' AND session_id IS NULL))`, now)
		if err != nil {
			return err
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// MarkReviewed signs off an emergency access after the fact.
func (r *RequestRepo) MarkReviewed(ctx context.Context, s access.Scope, requestID, reviewerID uuid.UUID,
	note string, at time.Time) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE access_requests SET reviewed_by=$2, reviewed_at=$3, review_note=$4
			WHERE id=$1 AND is_emergency`, requestID, reviewerID, at, note)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return access.ErrNotFound
		}
		return nil
	})
}

// ---- grants ---------------------------------------------------------------

// GrantRepo implements access.GrantRepository.
type GrantRepo struct{ db *DB }

// NewGrantRepo constructs a GrantRepo.
func NewGrantRepo(db *DB) *GrantRepo { return &GrantRepo{db: db} }

const grantCols = `g.id, g.organization_id, g.user_id, g.device_id, g.granted_by, g.request_id,
	g.expires_at, g.revoked_at, g.revoked_by, g.created_at`

func scanGrant(row pgx.Row, extra ...any) (*access.Grant, error) {
	var g access.Grant
	dest := []any{&g.ID, &g.OrganizationID, &g.UserID, &g.DeviceID, &g.GrantedBy, &g.RequestID,
		&g.ExpiresAt, &g.RevokedAt, &g.RevokedBy, &g.CreatedAt}
	dest = append(dest, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	return &g, nil
}

// Create inserts a standing grant, replacing any live one for the same pair.
func (r *GrantRepo) Create(ctx context.Context, s access.Scope, g *access.Grant) error {
	return r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		// uq_grant_live allows one live grant per (user, device). Re-granting
		// supersedes rather than colliding: the approver's intent is "this person
		// may reach this device", not "add a second row saying so".
		if _, err := tx.Exec(ctx, `
			UPDATE device_access_grants SET revoked_at=now(), revoked_by=$3
			WHERE user_id=$1 AND device_id=$2 AND revoked_at IS NULL`,
			g.UserID, g.DeviceID, g.GrantedBy); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO device_access_grants (id, organization_id, user_id, device_id,
				granted_by, request_id, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			g.ID, g.OrganizationID, g.UserID, g.DeviceID, g.GrantedBy, g.RequestID, g.ExpiresAt).
			Scan(&g.CreatedAt)
	})
}

// GetByID loads a grant.
func (r *GrantRepo) GetByID(ctx context.Context, s access.Scope, id uuid.UUID) (*access.Grant, error) {
	var g *access.Grant
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+grantCols+` FROM device_access_grants g WHERE g.id=$1`, id)
		var e error
		g, e = scanGrant(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		return e
	})
	return g, err
}

// List returns grants matching a filter, newest first.
func (r *GrantRepo) List(ctx context.Context, s access.Scope, f access.GrantFilter) ([]access.Grant, error) {
	limit := normalizeLimit(f.Limit)
	var out []access.Grant
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		q := `SELECT ` + grantCols + `, COALESCE(u.email::text, ''), COALESCE(d.name, ''),
				COALESCE(gb.email::text, '')
			FROM device_access_grants g
			LEFT JOIN users u ON u.id = g.user_id
			LEFT JOIN devices d ON d.id = g.device_id
			LEFT JOIN users gb ON gb.id = g.granted_by
			WHERE 1=1`
		args := []any{}
		if f.LiveOnly {
			q += ` AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())`
		}
		if f.UserID != nil {
			args = append(args, *f.UserID)
			q += ` AND g.user_id = $` + strconv.Itoa(len(args))
		}
		if f.DeviceID != nil {
			args = append(args, *f.DeviceID)
			q += ` AND g.device_id = $` + strconv.Itoa(len(args))
		}
		args = append(args, limit)
		q += ` ORDER BY g.created_at DESC LIMIT $` + strconv.Itoa(len(args))

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g access.Grant
			if e := rows.Scan(&g.ID, &g.OrganizationID, &g.UserID, &g.DeviceID, &g.GrantedBy,
				&g.RequestID, &g.ExpiresAt, &g.RevokedAt, &g.RevokedBy, &g.CreatedAt,
				&g.UserEmail, &g.DeviceName, &g.GrantedByEmail); e != nil {
				return e
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// Live returns the unrevoked, unexpired grant for a user on a device.
func (r *GrantRepo) Live(ctx context.Context, s access.Scope, userID, deviceID uuid.UUID, now time.Time) (*access.Grant, error) {
	var g *access.Grant
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+grantCols+` FROM device_access_grants g
			WHERE g.user_id=$1 AND g.device_id=$2 AND g.revoked_at IS NULL
			  AND (g.expires_at IS NULL OR g.expires_at > $3)
			LIMIT 1`, userID, deviceID, now)
		var e error
		g, e = scanGrant(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		return e
	})
	return g, err
}

// Revoke withdraws a grant and returns it, so the caller can terminate whatever
// session it was holding open.
func (r *GrantRepo) Revoke(ctx context.Context, s access.Scope, id, by uuid.UUID, at time.Time) (*access.Grant, error) {
	var g *access.Grant
	err := r.db.WithScopeIDs(ctx, s.OrganizationID, s.IsSuperAdmin, func(tx pgx.Tx) error {
		// Aliased, because grantCols is qualified with "g." for the joined reads and
		// a bare UPDATE ... RETURNING has no alias to resolve it against.
		row := tx.QueryRow(ctx, `
			UPDATE device_access_grants AS g SET revoked_at=$2, revoked_by=$3
			WHERE g.id=$1 AND g.revoked_at IS NULL
			RETURNING `+grantCols, id, at, by)
		var e error
		g, e = scanGrant(row)
		if errors.Is(e, pgx.ErrNoRows) {
			return access.ErrNotFound
		}
		return e
	})
	return g, err
}
