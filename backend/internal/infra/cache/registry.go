package cache

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// LiveRegistry tracks active access sessions in Redis for real-time monitoring
// and cross-node termination signalling. It implements access.LiveRegistry.
type LiveRegistry struct {
	rdb *redis.Client
}

// NewLiveRegistry constructs a LiveRegistry.
func NewLiveRegistry(rdb *redis.Client) *LiveRegistry { return &LiveRegistry{rdb: rdb} }

func orgKey(orgID uuid.UUID) string { return "live:org:" + orgID.String() }

const terminateChannel = "live:terminate"

// Add registers a session as active for an organization.
func (r *LiveRegistry) Add(ctx context.Context, orgID, sessionID uuid.UUID, ttl time.Duration) error {
	key := orgKey(orgID)
	if err := r.rdb.SAdd(ctx, key, sessionID.String()).Err(); err != nil {
		return err
	}
	if ttl > 0 {
		return r.rdb.Expire(ctx, key, ttl).Err()
	}
	return nil
}

// Remove deregisters a session.
func (r *LiveRegistry) Remove(ctx context.Context, orgID, sessionID uuid.UUID) error {
	return r.rdb.SRem(ctx, orgKey(orgID), sessionID.String()).Err()
}

// ListActive returns the active session ids for an organization.
func (r *LiveRegistry) ListActive(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	members, err := r.rdb.SMembers(ctx, orgKey(orgID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		if id, err := uuid.Parse(m); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// SignalTerminate publishes a termination request for a session that other
// gateway nodes subscribe to.
func (r *LiveRegistry) SignalTerminate(ctx context.Context, sessionID uuid.UUID) error {
	return r.rdb.Publish(ctx, terminateChannel, sessionID.String()).Err()
}

// SubscribeTerminate blocks, invoking handle for every session-termination
// signal published (via SignalTerminate) by any node, until ctx is cancelled.
// This is the consumer half of cross-node termination: a gateway node uses it to
// tear down a session's local in-memory proxy state even when the terminate
// request was handled on a different node — without it, a terminated session
// keeps serving on any node that didn't process the terminate itself.
func (r *LiveRegistry) SubscribeTerminate(ctx context.Context, handle func(sessionID uuid.UUID)) error {
	sub := r.rdb.Subscribe(ctx, terminateChannel)
	defer func() { _ = sub.Close() }()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			if id, err := uuid.Parse(msg.Payload); err == nil {
				handle(id)
			}
		}
	}
}
