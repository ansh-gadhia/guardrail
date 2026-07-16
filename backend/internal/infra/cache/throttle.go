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
}

// NewThrottle builds a throttle allowing up to max failures per window.
func NewThrottle(rdb *redis.Client, max int, window time.Duration) *Throttle {
	return &Throttle{rdb: rdb, max: max, window: window, prefix: "throttle:"}
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
		// Fail open on cache errors: account-level lockout is the hard guard.
		return true, 0, err
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
		return err
	}
	if n == 1 {
		return t.rdb.Expire(ctx, k, t.window).Err()
	}
	return nil
}

// Reset clears the counter after a successful login.
func (t *Throttle) Reset(ctx context.Context, key string) error {
	return t.rdb.Del(ctx, t.prefix+key).Err()
}
