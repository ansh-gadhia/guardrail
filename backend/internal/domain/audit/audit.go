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
