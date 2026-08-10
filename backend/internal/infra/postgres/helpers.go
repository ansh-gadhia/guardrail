package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

const (
	defaultLimit = 50
	maxLimit     = 200
	// maxExportLimit bounds a paged listing that is being drained for export.
	// Higher than maxLimit because the caller is deliberately asking for the
	// whole filtered set, and bounded anyway because "whole" is not a promise a
	// tenant with years of history should be able to extract in one response.
	maxExportLimit = 5000
)

func normalizeLimit(l int) int { return normalizeLimitUpTo(l, maxLimit) }

func normalizeLimitUpTo(l, ceiling int) int {
	switch {
	case l <= 0:
		return defaultLimit
	case l > ceiling:
		return ceiling
	default:
		return l
	}
}

// mapWriteErr translates PostgreSQL constraint violations into domain errors so
// the delivery layer can return the right status without importing pgx.
func mapWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return iam.ErrConflict
		case "23503": // foreign_key_violation
			return iam.ErrNotFound
		}
	}
	return err
}
