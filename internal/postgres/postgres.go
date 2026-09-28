// Package postgres owns the database connection pool and the schema migrations.
package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig describes how the pool should be built. It mirrors the DB section of
// the process configuration without importing it, so this package stays usable
// from tests and from the migration tool.
type PoolConfig struct {
	DSN             string
	MaxConns        int
	MinConns        int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	ConnectTimeout  time.Duration
}

// Connect opens a connection pool and verifies it can reach the database.
//
// Verifying up front is the point: a pool that is created lazily turns a wrong
// password into a confusing error on the first request instead of a clear failure
// at startup.
func Connect(ctx context.Context, cfg PoolConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}

	maxConns, err := toInt32("MaxConns", cfg.MaxConns)
	if err != nil {
		return nil, err
	}
	minConns, err := toInt32("MinConns", cfg.MinConns)
	if err != nil {
		return nil, err
	}

	poolCfg.MaxConns = maxConns
	poolCfg.MinConns = minConns
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	poolCfg.MaxConnIdleTime = cfg.ConnMaxIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	// Every timestamp the panel stores is UTC. Pinning the session timezone means
	// a server with a local TimeZone setting cannot quietly shift date_trunc
	// results or partition boundary comparisons.
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolCfg.ConnConfig.RuntimeParams["timezone"] = "UTC"

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return pool, nil
}

// toInt32 converts a pool size to the width pgxpool expects, refusing values that
// would wrap. Configuration already bounds these, so a failure here means the
// caller built a PoolConfig by hand and got it wrong.
func toInt32(name string, v int) (int32, error) {
	if v < 0 || v > math.MaxInt32 {
		return 0, fmt.Errorf("postgres: %s value %d is out of range", name, v)
	}
	return int32(v), nil
}
