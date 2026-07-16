package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

func normalizeLimit(l int) int {
	switch {
	case l <= 0:
		return defaultLimit
	case l > maxLimit:
		return maxLimit
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
