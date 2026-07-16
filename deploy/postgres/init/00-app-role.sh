#!/bin/sh
# Runs once at first database initialization (before migrations). Creates the
# least-privilege application login role. GuardRail's API connects as this
# NON-superuser role so PostgreSQL Row-Level Security is actually enforced
# (superusers bypass RLS). Migrations run as the superuser and grant this role
# the exact table privileges it needs.
set -eu

: "${GUARDRAIL_DB_APP_PASSWORD:?GUARDRAIL_DB_APP_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'guardrail_app') THEN
            CREATE ROLE guardrail_app LOGIN PASSWORD '${GUARDRAIL_DB_APP_PASSWORD}';
        ELSE
            ALTER ROLE guardrail_app LOGIN PASSWORD '${GUARDRAIL_DB_APP_PASSWORD}';
        END IF;
    END
    \$\$;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO guardrail_app;
SQL
