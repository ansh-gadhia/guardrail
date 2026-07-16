#!/usr/bin/env bash
# Run the GuardRail API as a NATIVE HOST process.
#
# Why native: a container network often cannot reach LAN management UIs (e.g.
# https://10.200.10.1:2443) while the host can, and GuardRail's whole job is to
# broker those. So the API has to run where the devices are reachable. It also
# serves the web console (GUARDRAIL_WEB_DIR), which keeps browser, API and /proxy
# on one origin.
#
# Datastores still run in the compose stack, published on host loopback. Secrets
# come from the repo .env, so credentials sealed under the master key decrypt.
#
# Normally you do not run this directly: `make install` (scripts/bootstrap.sh
# --native) sets everything up and calls it.
set -euo pipefail

# Every path below is derived from the repo root, so the checkout can live
# anywhere. Absolute paths here were a portability trap: copied to another server
# they point at nothing, and the failure surfaces as an empty console rather than
# as "that path does not exist".
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

set -a
# shellcheck disable=SC1091
source ./.env
set +a

export GUARDRAIL_ENV="${GUARDRAIL_ENV:-development}"
# Bind all interfaces so the console is reachable from the LAN (not just loopback).
export GUARDRAIL_HTTP_ADDR="${GUARDRAIL_HTTP_ADDR:-0.0.0.0:8080}"
# Connect as the least-privilege app role (RLS enforced), over the loopback-
# published postgres. Password from .env.
export GUARDRAIL_POSTGRES_DSN="postgres://guardrail_app:${GUARDRAIL_DB_APP_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB:-guardrail}?sslmode=disable"
export GUARDRAIL_REDIS_ADDR="${GUARDRAIL_REDIS_ADDR:-127.0.0.1:6379}"

# RDP/VNC brokering. Off unless guacd is actually running, because enabling the
# gateways without a daemon behind them turns "no gateway for this device
# protocol" (honest, and true) into a connection that hangs until it times out.
# Start it with: docker compose --profile desktop up -d
export GUARDRAIL_GUACD_ADDR="${GUARDRAIL_GUACD_ADDR:-127.0.0.1:4822}"
if [ -z "${GUARDRAIL_DESKTOP_ENABLED:-}" ]; then
  if (exec 3<>"/dev/tcp/${GUARDRAIL_GUACD_ADDR%%:*}/${GUARDRAIL_GUACD_ADDR##*:}") 2>/dev/null; then
    export GUARDRAIL_DESKTOP_ENABLED=true
  else
    export GUARDRAIL_DESKTOP_ENABLED=false
    echo "note: no guacd at $GUARDRAIL_GUACD_ADDR — RDP/VNC devices will report no gateway." >&2
    echo "      start it with: docker compose --profile desktop up -d" >&2
  fi
fi
# Where guacd writes session recordings. This ONE path is both what guacd is told
# to write to (inside its container) and what this process reads back, so the
# compose bind mount maps it at the same absolute path on both sides. If they ever
# disagree, guacd records and the API collects nothing.
#
# Probed rather than assumed. An unwritable or missing directory here does not
# fail loudly on its own: guacd would record into its own container, this process
# would find no file, and the session would end with its evidence quietly absent.
# So if the path is not usable, the recording dir is set EMPTY, which makes
# CanRecord() false and the broker refuse a record-enabled desktop device up front
# with a message saying so. Loudly wrong beats quietly empty.
export GUARDRAIL_GUACD_RECORDING_DIR="${GUARDRAIL_GUACD_RECORDING_DIR:-/var/lib/guardrail/desktop-recordings}"
if [ -n "$GUARDRAIL_GUACD_RECORDING_DIR" ]; then
  if ! mkdir -p "$GUARDRAIL_GUACD_RECORDING_DIR" 2>/dev/null || [ ! -r "$GUARDRAIL_GUACD_RECORDING_DIR" ]; then
    echo "note: $GUARDRAIL_GUACD_RECORDING_DIR is not readable — desktop recording disabled." >&2
    echo "      record-enabled RDP/VNC devices will refuse to connect rather than record nothing." >&2
    export GUARDRAIL_GUACD_RECORDING_DIR=""
  fi
fi
export GUARDRAIL_REDIS_PASSWORD="${REDIS_PASSWORD:-}"
export GUARDRAIL_JWT_SIGNING_KEY GUARDRAIL_MASTER_KEY
# Serve the web console from the API (same origin as /api and /proxy). Prefer the
# built React SPA (frontend/dist); fall back to the single-file console.
if [ -f "$ROOT/frontend/dist/index.html" ]; then
  export GUARDRAIL_WEB_DIR="${GUARDRAIL_WEB_DIR:-$ROOT/frontend/dist}"
else
  export GUARDRAIL_WEB_DIR="${GUARDRAIL_WEB_DIR:-$ROOT/deploy/nginx/html}"
fi
# Serve HTTPS with the self-signed cert. This is required because proxied device
# UIs (e.g. FortiGate) force https:// and the browser upgrades subresources; over
# plain HTTP the iframe/new-tab requests get upgraded to a port with no TLS and
# fail with "refused to connect". Set GUARDRAIL_TLS_CERT="" to force plain HTTP.
export GUARDRAIL_TLS_CERT="${GUARDRAIL_TLS_CERT-$ROOT/deploy/tls/cert.pem}"
export GUARDRAIL_TLS_KEY="${GUARDRAIL_TLS_KEY-$ROOT/deploy/tls/key.pem}"

# Which origins the console may be reached from. Defaults to this host's own LAN
# addresses plus loopback, discovered at start rather than written down: a
# hardcoded IP is wrong the moment the server gets a new lease or moves.
if [ -z "${GUARDRAIL_CORS_ALLOW_ORIGINS:-}" ]; then
  port="${GUARDRAIL_HTTP_ADDR##*:}"
  origins="https://localhost:${port},https://127.0.0.1:${port}"
  while read -r ip; do
    [ -n "$ip" ] && origins="${origins},https://${ip}:${port}"
  done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')
  export GUARDRAIL_CORS_ALLOW_ORIGINS="$origins"
fi

# The binary to run. Defaults to what `make build` produces.
GUARDRAIL_BIN="${GUARDRAIL_BIN:-$ROOT/bin/guardrail}"
if [ ! -x "$GUARDRAIL_BIN" ]; then
  echo "fatal: no API binary at $GUARDRAIL_BIN — build it with 'make build'" >&2
  exit 1
fi

exec "$GUARDRAIL_BIN"
