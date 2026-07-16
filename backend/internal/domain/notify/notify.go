// Package notify is the notifications bounded context: channels (email, Slack,
// webhook) and a transactional outbox for reliable, retryable delivery.
package notify

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a channel does not exist in scope.
var ErrNotFound = errors.New("notify: not found")

// ChannelType enumerates delivery mechanisms.
type ChannelType string

const (
	ChannelEmail   ChannelType = "email"
	ChannelSlack   ChannelType = "slack"
	ChannelWebhook ChannelType = "webhook"
)

// Channel is a configured notification destination.
type Channel struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Type           ChannelType
	Config         map[string]any // e.g. {"url": "..."} or {"address": "..."}
	Events         []string       // subscribed events, "*" for all
	Enabled        bool
}

// Wants reports whether the channel is subscribed to an event.
func (c *Channel) Wants(event string) bool {
	if !c.Enabled {
		return false
	}
	for _, e := range c.Events {
		if e == "*" || e == event {
			return true
		}
	}
	return false
}

// Notification is an outbox entry: one message to one channel.
type Notification struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	ChannelID      uuid.UUID
	Event          string
	Payload        map[string]any
	Status         string
	Attempts       int
	LastError      string
	CreatedAt      time.Time
	SentAt         *time.Time
}

// Scope is the tenant scope for notification operations.
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}

// ChannelRepository persists notification channels.
type ChannelRepository interface {
	Create(ctx context.Context, s Scope, c *Channel) error
	List(ctx context.Context, s Scope) ([]Channel, error)
	Delete(ctx context.Context, s Scope, id uuid.UUID) error
	// ListForOrg returns all enabled channels for an org (used by fan-out, which
	// runs in a system context triggered by an event).
	ListForOrg(ctx context.Context, orgID uuid.UUID) ([]Channel, error)
}

// Outbox persists and drains queued notifications.
type Outbox interface {
	Enqueue(ctx context.Context, n *Notification) error
	ListPending(ctx context.Context, limit int) ([]Notification, error)
	MarkSent(ctx context.Context, id uuid.UUID, at time.Time) error
	MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error
}

// Sender delivers a single notification to its channel. Implementations exist
// per channel type (webhook, Slack, email).
type Sender interface {
	Send(ctx context.Context, ch Channel, event string, payload map[string]any) error
}
