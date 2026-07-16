//go:build integration

// Package test holds integration tests exercised with `-tags=integration`
// (see `make test-integration`). They require live Postgres and Redis, provided
// by docker compose or the CI service containers. This smoke test verifies the
// backing services are reachable using the same adapters the app uses.
package test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/guardrail/guardrail/internal/config"
	"github.com/guardrail/guardrail/internal/platform/cache"
	"github.com/guardrail/guardrail/internal/platform/database"
)

func TestBackingServicesReachable(t *testing.T) {
	dsn := os.Getenv("GUARDRAIL_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GUARDRAIL_POSTGRES_DSN not set; skipping integration smoke test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := database.New(ctx, config.PostgresConfig{DSN: dsn, MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour})
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	defer db.Close()
	if err := db.Health(ctx); err != nil {
		t.Fatalf("postgres health: %v", err)
	}

	rdb, err := cache.New(ctx, config.RedisConfig{
		Addr:     getEnvOr("GUARDRAIL_REDIS_ADDR", "localhost:6379"),
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	if err := rdb.Health(ctx); err != nil {
		t.Fatalf("redis health: %v", err)
	}
}

func getEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
