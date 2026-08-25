// Package audit is the tamper-evident audit-log bounded context. Events are
// append-only and hash-chained per organization. The domain defines the event
// shape and the recorder port; the infra layer implements the chaining and
// persistence.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Category groups related actions for filtering/reporting.
type Category string

const (
	CategoryAuth    Category = "authentication"
	CategoryAuthz   Category = "authorization"
	CategoryUser    Category = "user"
	CategoryOrg     Category = "organization"
	CategoryRole    Category = "role"
	CategoryDevice  Category = "device"
	CategorySession Category = "session"
	CategoryVault   Category = "credential"
)

// Result is the outcome recorded on an event.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
	// ResultPending is an action whose outcome is not this event's to report,
	// because somebody else has yet to decide it. Raising an access request is
	// the case it exists for: the request was filed successfully, and it was
	// neither granted nor refused at that moment. Recording it as denied — which
	// is what happened before — makes the log say the opposite of what the
	// approver went on to do, and the row keeps saying it forever, because the
	// chain is append-only. The outcome arrives as its own approval.granted or
	// approval.denied event carrying the same request_id.
	ResultPending Result = "pending"
)

// Event is a single audit record. Every mandated field is present; PrevHash and
// Hash are populated by the recorder as it links the per-org chain.
type Event struct {
	ID             uuid.UUID
	OrganizationID *uuid.UUID // nil for system-level events
	Timestamp      time.Time
	ActorID        *uuid.UUID
	ActorEmail     string
	Action         string
	Category       Category
	TargetType     string
	TargetID       string
	SessionID      *uuid.UUID
	IP             string
	UserAgent      string
	Result         Result
	Detail         map[string]any
}

// Recorder appends events to the tamper-evident log. Implementations compute the
// hash chain and must never update or delete existing rows.
type Recorder interface {
	Record(ctx context.Context, e Event) error
}

// ChainReport is the result of recomputing an organization's hash chain.
//
// The chain is the platform's strongest claim — events cannot be edited,
// deleted or reordered without detection — and until something recomputed it,
// that was an assertion rather than a demonstration. This is what turns it into
// one, and what a compliance reviewer can be shown.
type ChainReport struct {
	// OK is false when a link or a row failed to reproduce its hash.
	OK bool
	// Checked is how many events were walked.
	Checked int
	// From and To bound the range verified.
	From time.Time
	To   time.Time
	// BrokenAt names the first event that failed, when one did. Everything before
	// it verified; everything after it is unproven, because a chain cannot
	// establish anything past its first break.
	BrokenAt *uuid.UUID
	// BrokenAtTS is when that event claims to have happened.
	BrokenAtTS *time.Time
	// Reason says which check failed, in words an auditor can use.
	Reason string
	// Unverifiable counts events whose hash predates the current scheme. They
	// cannot be recomputed from what the database stored, so they are neither
	// proved nor accused; the report names how many there were.
	Unverifiable int
	// Truncated is true when the walk stopped at its row cap rather than at the
	// end of the chain. A truncated pass can still prove the part it read; it
	// cannot prove that nothing was appended beyond it, so the report says so
	// instead of implying a completeness it did not establish.
	Truncated bool
}

// Fail marks the report broken at this event. Only the first break is recorded:
// past it, nothing downstream can be trusted to mean anything, so listing more
// would suggest a precision the chain cannot offer.
func (r *ChainReport) Fail(e Event, reason string) {
	if !r.OK {
		return
	}
	id, ts := e.ID, e.Timestamp
	r.OK, r.BrokenAt, r.BrokenAtTS, r.Reason = false, &id, &ts, reason
}

// ChainVerifier recomputes a stored chain. Implemented by the audit repository.
type ChainVerifier interface {
	// VerifyChain walks up to limit events for an organization — nil for the
	// system chain, whose events belong to no tenant.
	VerifyChain(ctx context.Context, orgID *uuid.UUID, limit int) (*ChainReport, error)
}
