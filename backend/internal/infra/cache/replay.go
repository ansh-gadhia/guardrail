package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// ReplayStore makes a SIEM exchange token single-use. It implements
// iam.ReplayStore.
type ReplayStore struct {
	rdb    *redis.Client
	prefix string
}

// NewReplayStore constructs a replay store.
func NewReplayStore(rdb *redis.Client) *ReplayStore {
	return &ReplayStore{rdb: rdb, prefix: "sso:nonce:"}
}

// Consume records a nonce and reports whether it was unused.
//
// SetNX, not GET-then-SET. The two copies of a replayed token arrive at the same
// moment by definition — that is what a replay looks like on the wire — and a
// read followed by a write lets both find the key absent and both proceed. The
// atomicity is the mechanism, not an optimisation.
//
// A store error is returned as an error, never as "unused". GuardRail fails the
// sign-in closed on it, which is a deliberate departure from how a cache blip is
// usually handled here: the throttle a few files over fails OPEN because account
// lockout still backstops it, but nothing backstops a replayed exchange token.
// It is a bearer credential whose single-use property is enforced in exactly one
// place, and on a privileged-access broker the session it opens can connect to a
// device. Redis is also already a hard dependency of this process — it is in the
// readiness probe — so a deployment that cannot reach it is not serving logins
// anyway, and failing open here would buy availability that does not exist.
func (s *ReplayStore) Consume(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, s.prefix+nonce, 1, ttl).Result()
}
