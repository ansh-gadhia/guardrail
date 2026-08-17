package access

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ---- errors ---------------------------------------------------------------

// ErrApprovalRequired reports that a connect was refused pending a decision.
// It is not a failure: a request has been raised and the caller should wait on
// it. The delivery layer answers 202 rather than an error status.
var ErrApprovalRequired = errors.New("access: approval required")

// ErrRequestNotPending is returned when deciding a request that has already
// been decided, expired or cancelled.
var ErrRequestNotPending = errors.New("access: request is no longer pending")

// ErrCannotDecide is returned when the would-be approver does not outrank the
// requester. It covers self-approval without a separate rule: a person never
// outranks themselves.
var ErrCannotDecide = errors.New("access: you do not outrank this request")

// ErrAlreadyDecided is returned when somebody decides a request twice. The
// two-person rule counts distinct people, so a second vote from the same
// approver is refused rather than counted.
var ErrAlreadyDecided = errors.New("access: you have already decided this request")

// ErrRequestNotApproved is returned when redeeming a request that was never
// approved, or whose approval has since lapsed.
var ErrRequestNotApproved = errors.New("access: request is not approved")

// ErrTooManyRequests is returned when one person raises requests faster than
// approvers could reasonably answer them.
var ErrTooManyRequests = errors.New("access: too many pending requests")

// ErrNoApprover is returned when a device is gated but nobody who outranks the
// requester could ever decide it. Raised at request time rather than leaving
// somebody waiting on a decision that cannot arrive.
var ErrNoApprover = errors.New("access: nobody can approve this request")

// ---- values ---------------------------------------------------------------

// RequestStatus is where a request sits in its lifecycle.
type RequestStatus string

const (
	RequestPending   RequestStatus = "pending"
	RequestApproved  RequestStatus = "approved"
	RequestDenied    RequestStatus = "denied"
	RequestExpired   RequestStatus = "expired"
	RequestCancelled RequestStatus = "cancelled"
)

// GrantScope is which button the approver pressed.
type GrantScope string

const (
	// GrantOnce authorizes this connect and nothing else.
	GrantOnce GrantScope = "once"
	// GrantAlways additionally writes a standing grant, which is a change to
	// future authorization rather than a decision about this request — see Grant.
	GrantAlways GrantScope = "always"
)

// DecisionApprove and DecisionDeny are the two votes.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// DefaultRequestTTL is how long a request waits before it escalates, and then
// how long it waits again before it expires.
//
// It also bounds an approved-but-unredeemed request. An approval that stays
// redeemable for a week is not "allow once", it is a standing grant that nobody
// chose to write down.
const DefaultRequestTTL = 30 * time.Minute

// MaxPendingPerUser caps how many requests one person can have outstanding, so
// a frustrated operator cannot bury every approver in notifications.
const MaxPendingPerUser = 5

// ---- aggregates -----------------------------------------------------------

// Request is somebody asking to reach a device they are entitled to but not
// yet cleared for.
type Request struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	DeviceID       uuid.UUID
	Status         RequestStatus
	// Reason is mandatory. An approver deciding without one is guessing, and it
	// is the field an auditor actually reads six months later.
	Reason string
	// RequestedMinutes is the window the requester asked for; GrantedMinutes is
	// what they got. An approver may shorten but never silently lengthen.
	RequestedMinutes int
	GrantedMinutes   *int
	GrantScope       *GrantScope
	// MinApprovals and RequesterLevel are snapshotted at request time: raising a
	// device's bar, or the requester's rank, must not retroactively change a
	// decision already being made.
	MinApprovals   int
	RequesterLevel int
	// IsEmergency marks access taken first and reviewed afterwards.
	IsEmergency bool
	ReviewedBy  *uuid.UUID
	ReviewedAt  *time.Time
	ReviewNote  string
	// EscalatedLevel is the rank this request has climbed to after going
	// unanswered.
	EscalatedLevel *int
	SessionID      *uuid.UUID
	ExpiresAt      time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Projections, populated on read for display.
	Decisions      []Decision
	RequesterEmail string
	DeviceName     string
}

// Decision is one approver's vote.
type Decision struct {
	RequestID      uuid.UUID
	DecidedBy      uuid.UUID
	Decision       string
	Note           string
	DecidedAt      time.Time
	DecidedByEmail string
}

// Approvals counts the distinct people who have approved.
func (r *Request) Approvals() int {
	n := 0
	for i := range r.Decisions {
		if r.Decisions[i].Decision == DecisionApprove {
			n++
		}
	}
	return n
}

// Satisfied reports whether enough people have approved.
func (r *Request) Satisfied() bool { return r.Approvals() >= r.EffectiveMinApprovals() }

// EffectiveMinApprovals never returns less than one. A stored zero would gate a
// device and then require nothing to open it, which is worse than not gating it.
func (r *Request) EffectiveMinApprovals() int {
	if r.MinApprovals < 1 {
		return 1
	}
	return r.MinApprovals
}

// Denied reports whether anybody voted to deny. One denial settles it: the
// two-person rule raises the bar for granting access, never for refusing it.
func (r *Request) Denied() bool {
	for i := range r.Decisions {
		if r.Decisions[i].Decision == DecisionDeny {
			return true
		}
	}
	return false
}

// DecidedBy reports whether this person has already voted.
func (r *Request) DecidedBy(userID uuid.UUID) bool {
	for i := range r.Decisions {
		if r.Decisions[i].DecidedBy == userID {
			return true
		}
	}
	return false
}

// Redeemable reports whether this request can still be turned into a session.
//
// An "allow all time" approval is deliberately NOT redeemable on its own. Its
// authorization lives in the Grant it created, and the grant is the thing with
// a list and a revoke button. Leaving the request independently redeemable made
// revocation a half-measure: an administrator revoked the standing access, the
// operator reconnected anyway on the leftover approval, and the audit trail
// showed access granted after it had been withdrawn.
func (r *Request) Redeemable(now time.Time) bool {
	if r.Status != RequestApproved || r.SessionID != nil || !now.Before(r.ExpiresAt) {
		return false
	}
	return r.GrantScope == nil || *r.GrantScope == GrantOnce
}

// Window is how long a session opened from this request may run.
func (r *Request) Window(fallback time.Duration) time.Duration {
	if r.GrantedMinutes != nil && *r.GrantedMinutes > 0 {
		return time.Duration(*r.GrantedMinutes) * time.Minute
	}
	if r.RequestedMinutes > 0 {
		return time.Duration(r.RequestedMinutes) * time.Minute
	}
	return fallback
}

// Grant is standing permission for one person on one device — the "allow all
// time" button.
//
// It is a separate aggregate from Request on purpose. Allow-once and deny answer
// the request in front of you; allow-always changes future authorization, and
// authorization that can only accumulate and can never be enumerated is how a
// privileged-access deployment rots. This has a list and a revoke path.
type Grant struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	DeviceID       uuid.UUID
	GrantedBy      *uuid.UUID
	RequestID      *uuid.UUID
	// ExpiresAt nil means "all time". The field exists although no button sets
	// it, so "allow until Friday" is a UI change rather than a migration.
	ExpiresAt *time.Time
	RevokedAt *time.Time
	RevokedBy *uuid.UUID
	CreatedAt time.Time

	UserEmail      string
	DeviceName     string
	GrantedByEmail string
}

// Live reports whether the grant authorizes a connect right now.
func (g *Grant) Live(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	return g.ExpiresAt == nil || now.Before(*g.ExpiresAt)
}

// ---- filters --------------------------------------------------------------

// RequestFilter narrows a request listing.
type RequestFilter struct {
	Status   RequestStatus
	UserID   *uuid.UUID
	DeviceID *uuid.UUID
	// PendingOnly restricts to requests still awaiting a decision.
	PendingOnly bool
	// UnreviewedEmergency restricts to emergency access nobody has signed off.
	UnreviewedEmergency bool
	Limit               int
}

// GrantFilter narrows a grant listing.
type GrantFilter struct {
	UserID   *uuid.UUID
	DeviceID *uuid.UUID
	// LiveOnly hides revoked and expired grants.
	LiveOnly bool
	Limit    int
}

// ---- ports ----------------------------------------------------------------

// RequestRepository persists access requests (tenant-scoped).
type RequestRepository interface {
	Create(ctx context.Context, s Scope, r *Request) error
	GetByID(ctx context.Context, s Scope, id uuid.UUID) (*Request, error)
	List(ctx context.Context, s Scope, f RequestFilter) ([]Request, error)
	// AddDecision records one vote and settles the request's status in the same
	// transaction, so two approvers deciding at once cannot both see "one more
	// needed" and leave the request short.
	AddDecision(ctx context.Context, s Scope, requestID, deciderID uuid.UUID, d Decision,
		approverLevel int, isSuperAdmin bool) (*Request, error)
	// SetOutcome records the window and scope an approver settled on, before the
	// vote is cast, so AddDecision stays a pure vote.
	SetOutcome(ctx context.Context, s Scope, requestID uuid.UUID, grantedMinutes *int, scope *GrantScope) error
	// Redeem attaches a session to an approved request, exactly once.
	Redeem(ctx context.Context, s Scope, requestID, sessionID uuid.UUID, now time.Time) error
	// Cancel withdraws a pending request raised by this user.
	Cancel(ctx context.Context, s Scope, requestID, userID uuid.UUID) error
	// PendingFor returns this user's live request for a device, if any.
	PendingFor(ctx context.Context, s Scope, userID, deviceID uuid.UUID, now time.Time) (*Request, error)
	// CountPending counts a user's outstanding requests, for rate limiting.
	CountPending(ctx context.Context, s Scope, userID uuid.UUID) (int, error)
	// Escalate raises unanswered requests one rank and returns how many moved.
	// Runs unscoped across tenants, like the session reaper.
	Escalate(ctx context.Context, now time.Time) (int, error)
	// ExpireOverdue closes out requests nobody answered in time.
	ExpireOverdue(ctx context.Context, now time.Time) (int, error)
	// MarkReviewed signs off an emergency access.
	MarkReviewed(ctx context.Context, s Scope, requestID, reviewerID uuid.UUID, note string, at time.Time) error
}

// GrantRepository persists standing grants (tenant-scoped).
type GrantRepository interface {
	Create(ctx context.Context, s Scope, g *Grant) error
	GetByID(ctx context.Context, s Scope, id uuid.UUID) (*Grant, error)
	List(ctx context.Context, s Scope, f GrantFilter) ([]Grant, error)
	// Live returns the unrevoked, unexpired grant for a user on a device.
	Live(ctx context.Context, s Scope, userID, deviceID uuid.UUID, now time.Time) (*Grant, error)
	// Revoke withdraws a grant and returns it, so the caller can terminate any
	// session it authorized.
	Revoke(ctx context.Context, s Scope, id, by uuid.UUID, at time.Time) (*Grant, error)
}

// Ranker answers "who outranks whom" for the approval gate, and whether a
// device is approvable at all.
type Ranker interface {
	// LevelFor returns a user's effective rank.
	LevelFor(ctx context.Context, s Scope, userID uuid.UUID) (int, error)
	// ApproversAbove counts active users who hold approval:decide and outrank
	// the given level.
	ApproversAbove(ctx context.Context, s Scope, level int) (int, error)
}
