// Package notify is the application layer for notifications: it fans events out
// to subscribed channels via a transactional outbox, drains the outbox with
// retries, and manages channels.
package notify

import (
	"context"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/domain/notify"
)

// Service implements the notification use cases and the access.Notifier port.
type Service struct {
	channels notify.ChannelRepository
	outbox   notify.Outbox
	sender   notify.Sender
	clock    iam.Clock
	audit    audit.Recorder // optional; nil disables auditing of channel changes
}

// NewService constructs the notify service. rec may be nil to disable auditing.
func NewService(channels notify.ChannelRepository, outbox notify.Outbox, sender notify.Sender, clock iam.Clock, rec audit.Recorder) *Service {
	if clock == nil {
		clock = iam.SystemClock{}
	}
	return &Service{channels: channels, outbox: outbox, sender: sender, clock: clock, audit: rec}
}

// Notify fans an event out to every subscribed channel by enqueuing outbox rows.
// It is best-effort and never returns an error to its caller (the broker).
func (s *Service) Notify(ctx context.Context, orgID uuid.UUID, event string, payload map[string]any) {
	channels, err := s.channels.ListForOrg(ctx, orgID)
	if err != nil {
		return
	}
	for i := range channels {
		if !channels[i].Wants(event) {
			continue
		}
		_ = s.outbox.Enqueue(ctx, &notify.Notification{
			ID: uuid.New(), OrganizationID: orgID, ChannelID: channels[i].ID, Event: event, Payload: payload,
		})
	}
}

// Dispatch drains up to limit pending notifications, sending each via its
// channel. Returns counts of sent and failed. Intended to be called on a ticker.
func (s *Service) Dispatch(ctx context.Context, limit int) (sent, failed int) {
	pending, err := s.outbox.ListPending(ctx, limit)
	if err != nil || len(pending) == 0 {
		return 0, 0
	}
	// Load channels for the orgs represented in this batch.
	chanByID := map[uuid.UUID]notify.Channel{}
	seenOrg := map[uuid.UUID]bool{}
	for _, n := range pending {
		if seenOrg[n.OrganizationID] {
			continue
		}
		seenOrg[n.OrganizationID] = true
		chs, err := s.channels.ListForOrg(ctx, n.OrganizationID)
		if err != nil {
			continue
		}
		for _, ch := range chs {
			chanByID[ch.ID] = ch
		}
	}

	for _, n := range pending {
		ch, ok := chanByID[n.ChannelID]
		if !ok {
			_ = s.outbox.MarkFailed(ctx, n.ID, "channel not found or disabled")
			failed++
			continue
		}
		if err := s.sender.Send(ctx, ch, n.Event, n.Payload); err != nil {
			_ = s.outbox.MarkFailed(ctx, n.ID, err.Error())
			failed++
			continue
		}
		_ = s.outbox.MarkSent(ctx, n.ID, s.clock.Now())
		sent++
	}
	return sent, failed
}

// ---- channel management ----

// ChannelInput describes a channel to create.
type ChannelInput struct {
	Name   string
	Type   notify.ChannelType
	Config map[string]any
	Events []string
}

func scopeOf(a iam.Claims) notify.Scope {
	return notify.Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

// CreateChannel creates a notification channel.
func (s *Service) CreateChannel(ctx context.Context, actor iam.Claims, in ChannelInput) (*notify.Channel, error) {
	events := in.Events
	if events == nil {
		events = []string{"*"}
	}
	ch := &notify.Channel{
		ID: uuid.New(), OrganizationID: actor.OrganizationID, Name: in.Name, Type: in.Type,
		Config: in.Config, Events: events, Enabled: true,
	}
	if err := s.channels.Create(ctx, scopeOf(actor), ch); err != nil {
		return nil, err
	}
	s.record(ctx, actor, "channel.create", ch.ID, map[string]any{"name": ch.Name, "type": ch.Type})
	return ch, nil
}

// ListChannels returns channels in scope.
func (s *Service) ListChannels(ctx context.Context, actor iam.Claims) ([]notify.Channel, error) {
	return s.channels.List(ctx, scopeOf(actor))
}

// DeleteChannel removes a channel.
func (s *Service) DeleteChannel(ctx context.Context, actor iam.Claims, id uuid.UUID) error {
	if err := s.channels.Delete(ctx, scopeOf(actor), id); err != nil {
		return err
	}
	s.record(ctx, actor, "channel.delete", id, nil)
	return nil
}

// record is a best-effort audit helper for channel changes.
func (s *Service) record(ctx context.Context, actor iam.Claims, action string, channelID uuid.UUID, detail map[string]any) {
	if s.audit == nil {
		return
	}
	org := actor.OrganizationID
	uid := actor.UserID
	_ = s.audit.Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
		Action: action, Category: audit.CategoryOrg, TargetType: "notification_channel", TargetID: channelID.String(),
		Result: audit.ResultSuccess, Detail: detail,
	})
}
