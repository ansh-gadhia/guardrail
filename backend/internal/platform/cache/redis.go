// Package cache provides the Redis client adapter used for auth sessions, rate
// limiting, distributed locks, the live-session registry, and pub/sub.
package cache

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/guardrail/guardrail/internal/config"
)

// Client wraps go-redis. Higher layers depend on narrow interfaces (e.g. a
// RateLimiter or SessionStore) implemented on top of this.
type Client struct {
	*redis.Client
}

// New creates and verifies a Redis client.
func New(ctx context.Context, cfg config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Client{Client: rdb}, nil
}

// Health verifies connectivity for the readiness probe.
func (c *Client) Health(ctx context.Context) error {
	return c.Ping(ctx).Err()
}
