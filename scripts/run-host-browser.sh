#!/usr/bin/env bash
# Run the GuardRail API natively with BROWSER-ISOLATION enabled.
#
# The web gateway renders each device UI in a server-side headless Chromium and
# streams the pixels to the user over a WebSocket (Chrome DevTools screencast),
# instead of reverse-proxying the device HTML. This is the CyberPAM/Guacamole
# model: it works with hostile SPAs (FortiGate), needs no HTML rewriting, and the
# device credential is typed into the real browser server-side — never exposed.
#
# Requires: a Chromium/Chrome binary (see GUARDRAIL_CHROME_PATH) and the compose
# postgres/redis published on host loopback (docker-compose.override.yml).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a
# shellcheck disable=SC1091
source ./.env
set +a

export GUARDRAIL_ENV="${GUARDRAIL_ENV:-development}"
# Default to :8443 because the reference CyberPAM container may hold :8080.
export GUARDRAIL_HTTP_ADDR="${GUARDRAIL_HTTP_ADDR:-:8443}"
export GUARDRAIL_POSTGRES_DSN="postgres://guardrail_app:${GUARDRAIL_DB_APP_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB:-guardrail}?sslmode=disable"
export GUARDRAIL_REDIS_ADDR="127.0.0.1:6379"
export GUARDRAIL_REDIS_PASSWORD="${REDIS_PASSWORD:-}"
export GUARDRAIL_JWT_SIGNING_KEY GUARDRAIL_MASTER_KEY
export GUARDRAIL_WEB_DIR="${GUARDRAIL_WEB_DIR:-/home/test/guardrail/frontend/dist}"
export GUARDRAIL_TLS_CERT="${GUARDRAIL_TLS_CERT-/home/test/guardrail/deploy/tls/cert.pem}"
export GUARDRAIL_TLS_KEY="${GUARDRAIL_TLS_KEY-/home/test/guardrail/deploy/tls/key.pem}"

# Browser isolation.
export GUARDRAIL_BROWSER_ISOLATION="${GUARDRAIL_BROWSER_ISOLATION:-true}"
export GUARDRAIL_CHROME_PATH="${GUARDRAIL_CHROME_PATH:-/tmp/chrome-linux64/chrome}"

export GUARDRAIL_CORS_ALLOW_ORIGINS="${GUARDRAIL_CORS_ALLOW_ORIGINS:-https://10.200.10.245:8443,https://127.0.0.1:8443}"

exec /tmp/guardrail-host
