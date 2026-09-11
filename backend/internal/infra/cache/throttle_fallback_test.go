package cache

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// deadRedis points at a port nothing is listening on, which is what a Redis
// outage looks like to this code.
func deadRedis(t *testing.T) *redis.Client {
	t.Helper()
	c := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The regression this exists for: Allow used to return (true, 0, err) on any
// cache error, so a Redis outage removed per-(ip,email) rate limiting entirely
// and an attacker got unlimited attempt SPEED until the Postgres account lockout
// caught up — which password spraying across many accounts never trips.
func TestThrottleStillBlocksWhenRedisIsDown(t *testing.T) {
	ctx := context.Background()
	th := NewThrottle(deadRedis(t), 3, time.Minute)
	const key = "login:10.0.0.1:op@corp"

	for i := range 3 {
		ok, _, err := th.Allow(ctx, key)
		if !ok {
			t.Fatalf("blocked after %d failures, threshold is 3", i)
		}
		if err != nil {
			t.Fatalf("Allow returned an error callers would read as 'let it through': %v", err)
		}
		_ = th.Fail(ctx, key)
	}

	ok, retry, err := th.Allow(ctx, key)
	if ok {
		t.Fatal("attempts still allowed past the threshold with Redis down")
	}
	// Callers do: if ok, _, e := Allow(...); e == nil && !ok { block }
	// A non-nil error here would discard the decision that was just made.
	if err != nil {
		t.Fatalf("Allow returned err=%v alongside a block; callers would ignore the block", err)
	}
	if retry <= 0 {
		t.Errorf("retry-after = %v, want the remaining window", retry)
	}
}

// A successful sign-in during an outage must not leave a stale in-memory
// counter that blocks the same person once Redis returns.
func TestThrottleResetClearsTheFallback(t *testing.T) {
	ctx := context.Background()
	th := NewThrottle(deadRedis(t), 1, time.Minute)
	const key = "login:10.0.0.1:op@corp"

	_ = th.Fail(ctx, key)
	if ok, _, _ := th.Allow(ctx, key); ok {
		t.Fatal("not blocked at the threshold")
	}
	_ = th.Reset(ctx, key) // returns a Redis error; the fallback must still clear
	if ok, _, _ := th.Allow(ctx, key); !ok {
		t.Fatal("Reset did not clear the in-memory counter")
	}
}

// Distinct accounts must not share a budget — password spraying is the case
// per-key limiting exists for.
func TestThrottleFallbackIsPerKey(t *testing.T) {
	ctx := context.Background()
	th := NewThrottle(deadRedis(t), 2, time.Minute)

	for range 2 {
		_ = th.Fail(ctx, "login:10.0.0.1:alice@corp")
	}
	if ok, _, _ := th.Allow(ctx, "login:10.0.0.1:alice@corp"); ok {
		t.Fatal("alice was not blocked")
	}
	if ok, _, _ := th.Allow(ctx, "login:10.0.0.1:bob@corp"); !ok {
		t.Fatal("bob was blocked by alice's failures")
	}
}
