// Package cache holds Redis-backed adapters for IAM (brute-force throttle) and,
// in later milestones, rate limiting and the live-session registry.
package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Throttle is a fixed-window brute-force guard backed by Redis. It implements
// the app/iam.Throttle port.
type Throttle struct {
	rdb    *redis.Client
	max    int
	window time.Duration
	prefix string
	// fallback keeps the guard working when Redis cannot answer. See
	// memthrottle.go for why this degrades rather than failing open or closed.
	fallback *memThrottle
}

// NewThrottle builds a throttle allowing up to maxFailures per window.
func NewThrottle(rdb *redis.Client, maxFailures int, window time.Duration) *Throttle {
	return &Throttle{
		rdb: rdb, max: maxFailures, window: window, prefix: "throttle:",
		fallback: newMemThrottle(maxFailures, window),
	}
}

// Allow reports whether an attempt for key may proceed. When blocked it returns
// the remaining window as retry-after.
func (t *Throttle) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	k := t.prefix + key
	n, err := t.rdb.Get(ctx, k).Int()
	if err == redis.Nil {
		return true, 0, nil
	}
	if err != nil {
		// Redis cannot answer. Fall back to the in-process counter rather than
		// waving the attempt through: this used to return (true, 0, err), which
		// removed per-(ip,email) rate limiting for the whole outage.
		//
		// The error is NOT propagated, deliberately. Callers treat a non-nil
		// error as "could not decide, let it through" — so returning one here
		// would discard the decision the fallback just made.
		ok, retry := t.fallback.allow(key)
		return ok, retry, nil
	}
	if n >= t.max {
		ttl, _ := t.rdb.TTL(ctx, k).Result()
		if ttl < 0 {
			ttl = t.window
		}
		return false, ttl, nil
	}
	return true, 0, nil
}

// Fail records a failed attempt, starting the window on the first failure.
func (t *Throttle) Fail(ctx context.Context, key string) error {
	k := t.prefix + key
	n, err := t.rdb.Incr(ctx, k).Result()
	if err != nil {
		// Counted in memory instead, so the window that Allow will consult is
		// the one this failure belongs to.
		t.fallback.fail(key)
		return err
	}
	if n == 1 {
		if eerr := t.rdb.Expire(ctx, k, t.window).Err(); eerr != nil {
			// The counter exists but has no expiry. Left alone: Allow treats a
			// missing TTL as a full window (see above), so the key cannot become
			// a permanent block.
			return eerr
		}
	}
	return nil
}

// Reset clears the counter after a successful login.
//
// Both stores, always. A successful sign-in during an outage must not leave a
// stale in-memory counter behind to block the same person once Redis returns.
func (t *Throttle) Reset(ctx context.Context, key string) error {
	t.fallback.reset(key)
	return t.rdb.Del(ctx, t.prefix+key).Err()
}
