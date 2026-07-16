// Package database provides the PostgreSQL connection pool adapter. It exposes a
// small surface so the rest of the app depends on an interface, not pgx
// directly (ports & adapters).
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/guardrail/guardrail/internal/config"
)

// Pool wraps a pgx connection pool. Repositories accept *Pool (or the narrower
// Querier interface) rather than importing pgx globally.
type Pool struct {
	*pgxpool.Pool
}

// New creates and verifies a connection pool. It pings the database so startup
// fails fast when Postgres is unreachable or misconfigured.
func New(ctx context.Context, cfg config.PostgresConfig) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Pool{Pool: pool}, nil
}

// Health verifies the pool can serve a query. Used by the readiness probe.
func (p *Pool) Health(ctx context.Context) error {
	return p.Ping(ctx)
}

// Close releases all connections.
func (p *Pool) Close() {
	if p.Pool != nil {
		p.Pool.Close()
	}
}
