#!/usr/bin/env bash
# Take a fresh server to a running GuardRail with one command.
#
# Everything here is idempotent: run it on a bare machine to install, and run it
# again after a `git pull` to migrate and restart. It never overwrites an existing
# .env, because that file holds the vault's master key — regenerating it would
# leave every stored credential undecryptable, which is data loss dressed up as a
# config refresh.
#
# What it does NOT do is decide anything for you. If a prerequisite is missing it
# says which and stops, rather than curl|sh-ing a package from the internet onto a
# machine that is about to hold privileged credentials.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

# --- output -----------------------------------------------------------------
# Colour only when a human is watching; CI logs and `tee` get plain text.
if [ -t 1 ]; then
    B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
    B=""; G=""; Y=""; R=""; D=""; N=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$B$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%serror:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
${B}GuardRail bootstrap${N} — fresh server to running stack, idempotent.

  ${B}scripts/bootstrap.sh${N} [options]

Options:
  --skip-build      Reuse the existing binary and console build.
  --no-start        Set everything up but do not start the API.
  --native          Run the API as a host process instead of in compose.
                    Required when devices live on a LAN the container cannot
                    reach; this is what this sandbox uses.
  -h, --help        Show this.

Run it again any time. It will not touch an existing .env.
EOF
}

SKIP_BUILD=0; NO_START=0; NATIVE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1 ;;
        --no-start)   NO_START=1 ;;
        --native)     NATIVE=1 ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage; die "unknown option: $1" ;;
    esac
    shift
done

# --- 1. prerequisites -------------------------------------------------------
# Checked all at once and reported together: finding out about three missing
# tools one failed run at a time is its own small punishment.
step "Checking prerequisites"
missing=()
have() { command -v "$1" >/dev/null 2>&1; }

have docker || missing+=("docker            — https://docs.docker.com/engine/install/")
if have docker && ! docker compose version >/dev/null 2>&1; then
    missing+=("docker compose v2 — the 'compose' plugin for docker")
fi
have openssl || missing+=("openssl           — apt install openssl")

# Go and Node are only needed when this run has to build ON THE HOST, which is
# only ever --native. Under compose the API image compiles the Go binary and the
# web image runs `npm ci && npm run build` inside itself, and nothing outside
# reads frontend/dist — so demanding a host toolchain there was asking a server to
# install Node in order to produce a directory no container mounts. It also made
# the console build the first thing to fail on a machine that never needed it.
if [ "$SKIP_BUILD" -eq 0 ] && [ "$NATIVE" -eq 1 ]; then
    if [ "$NATIVE" -eq 1 ]; then
        # PATH is set for the invoking shell, and Go's installer drops it in
        # /usr/local/go/bin without touching a non-login shell's PATH — a very
        # common way for "go: command not found" to mean "go is installed".
        # Version, not presence. Ubuntu 22.04's `go` is 1.18; go.mod asks for 1.26
        # and 1.18 predates the toolchain directive that would fetch it, so the
        # build dies as "package cmp is not in GOROOT" — which looks like a broken
        # install, not an old compiler. Catch it here where we can say so.
        gobin=""
        if have go; then gobin=$(command -v go)
        elif [ -x /usr/local/go/bin/go ]; then gobin=/usr/local/go/bin/go
        fi
        if [ -z "$gobin" ]; then
            missing+=("go 1.26+          — https://go.dev/dl/")
        else
            gov=$("$gobin" version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
            gomaj="${gov%%.*}"; gomin="${gov#*.}"
            if [ -z "$gov" ] || [ "$gomaj" -lt 1 ] || { [ "$gomaj" -eq 1 ] && [ "$gomin" -lt 26 ]; }; then
                missing+=("go 1.26+          — https://go.dev/dl/  (found go${gov:-?} at $gobin, too old)")
            fi
        fi
    fi
    # Native serves the console off the filesystem (GUARDRAIL_WEB_DIR ->
    # frontend/dist), so this run has to produce it.
    have npm || missing+=("node + npm        — https://nodejs.org/ (or nvm)")
fi

if [ ${#missing[@]} -gt 0 ]; then
    printf '\n%smissing prerequisites:%s\n\n' "$R" "$N" >&2
    for m in "${missing[@]}"; do printf '  - %s\n' "$m" >&2; done
    printf '\nInstall them and run this again.\n\n' >&2
    exit 1
fi
[ -x /usr/local/go/bin/go ] && ! have go && export PATH="$PATH:/usr/local/go/bin"
info "docker, compose$([ "$SKIP_BUILD" -eq 0 ] && [ "$NATIVE" -eq 1 ] && echo ", go, node") — all present"

docker info >/dev/null 2>&1 || die "docker is installed but not usable by $(whoami).
    Start it (systemctl start docker) or add yourself to the docker group."

# --- 2. configuration -------------------------------------------------------
# The one step that must never be redone. .env holds GUARDRAIL_MASTER_KEY, the
# KEK every vaulted credential is sealed under: replace it and the credentials are
# gone, with no error at boot and no sign of trouble until someone presses
# Connect. So an existing file is left exactly as it is.
step "Configuration (.env)"
if [ -f .env ]; then
    info "already exists — left untouched"
    info "${D}(it holds the vault master key; regenerating it would orphan every stored credential)${N}"
else
    [ -f .env.example ] || die ".env.example is missing; cannot generate a config"
    cp .env.example .env
    # A 48-byte base64 secret per placeholder, generated locally. Written with
    # python rather than sed so a '/' or '&' in the random value cannot corrupt
    # the file — a class of bug that only shows up on a lucky run.
    python3 - <<'PY' || die "failed to write generated secrets into .env"
import base64, os, re, secrets

def s(n=48):
    return base64.b64encode(secrets.token_bytes(n)).decode()

def pw(n=18):
    # Alphanumeric: this one ends up inside a postgres:// URL, where '/', '@' and
    # '#' would need escaping and would eventually meet code that forgets to.
    a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(a) for _ in range(n))

vals = {
    "GUARDRAIL_JWT_SIGNING_KEY": s(),
    "GUARDRAIL_MASTER_KEY": s(),
    "POSTGRES_PASSWORD": pw(),
    "GUARDRAIL_DB_APP_PASSWORD": pw(),
    "GUARDRAIL_ADMIN_PASSWORD": "GuardRail-" + pw(12) + "!",
}
src = open(".env").read()
for k, v in vals.items():
    src, n = re.subn(rf"(?m)^{k}=.*$", f"{k}={v}", src)
    if n != 1:
        raise SystemExit(f"expected exactly one {k}= line in .env.example, found {n}")
open(".env", "w").write(src)
os.chmod(".env", 0o600)
PY
    info "generated .env with fresh secrets ${D}(mode 0600)${N}"
    warn "the admin password is in .env as GUARDRAIL_ADMIN_PASSWORD — sign in and change it"
fi

set -a
# shellcheck disable=SC1091
source ./.env
set +a

# Refuse to proceed on a config that still carries the example's placeholders. The
# app would start and then fail in ways that do not name this file.
for var in GUARDRAIL_JWT_SIGNING_KEY GUARDRAIL_MASTER_KEY POSTGRES_PASSWORD GUARDRAIL_DB_APP_PASSWORD; do
    case "${!var:-}" in
        ""|CHANGE_ME*) die "$var in .env is unset or still the example placeholder.
    Generate one with:  openssl rand -base64 48" ;;
    esac
done

# --- 3. TLS -----------------------------------------------------------------
# Self-signed is the right default and a deliberate one: the console must be HTTPS
# because proxied device UIs force https:// and the browser upgrades subresources,
# so a plain-HTTP console breaks brokered sessions with "refused to connect".
step "TLS certificate"

# This host's own routable addresses — what someone types to reach the console.
host_ips() { ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; }

# Which of them the existing certificate does NOT name.
#
# Existence is not the same as validity, and checking only for a file is what let
# this rot: the certificate was generated when the machine had different IPs, the
# network moved, and the stale cert stayed. The console still loaded — a browser
# lets you click through a name mismatch — but WebSockets do not get that
# exception, so brokered desktop sessions failed with "the connection to the
# session was lost" while guacd logged a client that never answered. Nothing
# pointed at the certificate. So verify the SANs, not the filename.
cert_missing_ips() {
    local sans ip missing=""
    sans=$(openssl x509 -in deploy/tls/cert.pem -noout -ext subjectAltName 2>/dev/null || true)
    for ip in $(host_ips); do
        case "$sans" in *"IP Address:$ip"*) ;; *) missing="$missing $ip" ;; esac
    done
    printf '%s' "${missing# }"
}

generate_cert() {
    mkdir -p deploy/tls
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout deploy/tls/key.pem -out deploy/tls/cert.pem \
        -subj "/CN=guardrail" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1$(
            host_ips | awk '{printf ",IP:%s", $1}'
        )" >/dev/null 2>&1 || die "openssl could not generate a certificate"
    chmod 600 deploy/tls/key.pem
}

if [ -f deploy/tls/cert.pem ] && [ -f deploy/tls/key.pem ]; then
    missing=$(cert_missing_ips)
    if [ -n "$missing" ]; then
        warn "the certificate does not name this host's address(es):$missing"
        warn "regenerating — browsers that trusted the old one must accept the new one once"
        cp deploy/tls/cert.pem "deploy/tls/cert.pem.bak.$(date +%s)" 2>/dev/null || true
        generate_cert
        info "regenerated for localhost + $(host_ips | tr '\n' ' ')"
    else
        exp=$(openssl x509 -enddate -noout -in deploy/tls/cert.pem 2>/dev/null | cut -d= -f2 || echo "?")
        info "already present ${D}(expires $exp)${N}"
    fi
else
    generate_cert
    info "generated a self-signed certificate for localhost + this host's IPs"
    warn "browsers will warn on it; replace deploy/tls/*.pem with a real cert for production"
fi

# --- 3b. desktop recording directory ----------------------------------------
# guacd writes desktop recordings here and the API reads them back out, over a
# bind mount that exists at the same path on both sides.
#
# It has to be created HERE, with an owner, because Docker's answer is wrong in a
# way that does not look wrong. A missing bind-mount source is created by Docker
# as root, mode 755 — and neither process that uses it runs as root. guacd's
# response to "cannot open the recording" is to log it and serve the session
# anyway, so the desktop works, the recording silently does not, and GuardRail
# then reads an empty directory and finalizes a recording with no artifact: a
# session that claims to be recorded, with no evidence, found only when somebody
# goes looking. That is the exact failure this product exists to prevent.
#
# guacd writes each recording here as its own user (uid 1000, gid 1000 — kept as
# the image ships it, because a uid with no passwd entry has no HOME and FreeRDP
# then cannot build its cert store, which kills RDP at "Security negotiation
# failed"). guacd creates the files 0640 — group-readable (libguac/recording.c).
#
# So the directory is owned by guacd and setgid to guacd's group, and the API
# joins that group (docker-compose group_add: "1000"). Then:
#   owner 1000:1000   guacd writes; setgid stamps every recording group 1000
#   mode 2770         group 1000 has rwx, so the API (a member) reads a recording
#                     and unlinks it after storing (unlink needs write on the DIR)
# Nothing here depends on the API's own uid or primary gid — only on it being in
# group 1000, which compose guarantees. RBAC on the recording still applies at the
# API; this is only the OS-level file handover.
step "Desktop recording directory"
guac_rec_dir="${GUARDRAIL_GUACD_RECORDING_DIR:-/var/lib/guardrail/desktop-recordings}"
guacd_id=1000
if mkdir -p "$guac_rec_dir" 2>/dev/null; then
    # Idempotent, and re-run on purpose: a directory Docker already created
    # root-owned (or left 1000:65532 by an earlier version of this script) is
    # exactly the case being repaired, and it looks identical to a correct one
    # until guacd tries to write or the API tries to read.
    chown "$guacd_id:$guacd_id" "$guac_rec_dir" 2>/dev/null ||
        sudo chown "$guacd_id:$guacd_id" "$guac_rec_dir" 2>/dev/null || true
    chmod 2770 "$guac_rec_dir" 2>/dev/null || sudo chmod 2770 "$guac_rec_dir" 2>/dev/null || true
    ownership=$(stat -c '%u:%g' "$guac_rec_dir" 2>/dev/null || echo "?:?")
    if [ "$ownership" = "$guacd_id:$guacd_id" ]; then
        info "$guac_rec_dir ${D}(guacd:$guacd_id owns it; the API joins group $guacd_id to read)${N}"
    else
        warn "$guac_rec_dir is $ownership, not $guacd_id:$guacd_id."
        info "Desktop sessions will connect normally and record NOTHING, which is"
        info "the worst of both. Fix:"
        info "  ${B}sudo chown $guacd_id:$guacd_id $guac_rec_dir && sudo chmod 2770 $guac_rec_dir${N}"
    fi
else
    warn "could not create $guac_rec_dir — desktop recordings will not be captured."
    info "Create it with:"
    info "  ${B}sudo mkdir -p $guac_rec_dir${N}"
    info "  ${B}sudo chown $guacd_id:$guacd_id $guac_rec_dir && sudo chmod 2770 $guac_rec_dir${N}"
fi

# --- 4. datastores ----------------------------------------------------------
step "Starting datastores (postgres, redis)"
docker compose up -d postgres redis >/dev/null 2>&1 || die "docker compose could not start postgres/redis"

# Wait for readiness rather than sleeping. pg_isready answers the only question
# that matters, and a fixed sleep is either too short on a cold machine or wasted
# time on a warm one.
printf '    waiting for postgres'
for i in $(seq 1 60); do
    if docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-guardrail}" -q 2>/dev/null; then
        printf ' ready\n'; break
    fi
    [ "$i" -eq 60 ] && { printf '\n'; die "postgres did not become ready in 60s. Try: docker compose logs postgres"; }
    printf '.'; sleep 1
done

# --- 5. schema --------------------------------------------------------------
# Run through the same golang-migrate image compose uses, so there is exactly one
# definition of "apply the migrations" and no second path to drift out of sync.
step "Applying database migrations"
migrate_out=$(docker compose run --rm migrate 2>&1) || {
    printf '%s\n' "$migrate_out" >&2
    # The most common failure here is not a bad migration — it is a password
    # mismatch against a data volume from an earlier run. Postgres only applies
    # POSTGRES_PASSWORD (and creates the app role) when it FIRST initialises its
    # data directory; after that, changing the password in .env has no effect on
    # the stored role, so migrate authenticates with the wrong one. Name it, and
    # give the exact fix, rather than leaving the operator to guess.
    if printf '%s\n' "$migrate_out" | grep -qi "password authentication failed"; then
        die "migrations failed: the database rejected the password.

    This almost always means the 'pgdata' volume was created by an earlier run
    with a different password than the current .env. Postgres sets the password
    only when it first initialises the volume.

    On a fresh deploy with no data to keep:
        ${B}docker compose down -v && make install${N}
      (down -v wipes pgdata — and redis and recordings; do not use it once you
       have sessions/recordings you care about)

    To keep existing data instead, set the roles to match .env:
        docker compose up -d postgres
        docker compose exec postgres psql -U ${POSTGRES_USER:-guardrail} -d postgres \\
          -c \"ALTER USER ${POSTGRES_USER:-guardrail} PASSWORD '<POSTGRES_PASSWORD from .env>';\"
        docker compose exec postgres psql -U ${POSTGRES_USER:-guardrail} -d postgres \\
          -c \"ALTER USER guardrail_app PASSWORD '<GUARDRAIL_DB_APP_PASSWORD from .env>';\"
        make install"
    fi
    die "migrations failed. If it says 'Dirty database', a previous run died half-way:
    inspect it, fix the schema, then clear the flag before retrying."
}
printf '%s\n' "$migrate_out" | grep -qi "no change" && info "schema already up to date" || info "migrations applied"

step "Loading seed data (permissions, system roles, default org)"
docker compose run --rm seed >/dev/null 2>&1 || die "seed failed. Try: docker compose run --rm seed"
info "seeded ${D}(idempotent — ON CONFLICT DO NOTHING)${N}"

# --- 6. build ---------------------------------------------------------------
# Host builds are for --native only. Under compose both images build themselves
# from this same source (see backend/Dockerfile and frontend/Dockerfile), and
# `docker compose up -d --build` below is what runs them.
if [ "$SKIP_BUILD" -eq 0 ] && [ "$NATIVE" -eq 1 ]; then
    step "Building the web console"
    (cd frontend && npm ci --silent >/dev/null 2>&1 || npm install --silent >/dev/null 2>&1) \
        || die "npm install failed in frontend/"
    (cd frontend && npm run build >/dev/null 2>&1) || die "the console build failed. Try: cd frontend && npm run build"
    info "frontend/dist ready"

    step "Building the API binary"
    (cd backend && CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION:-dev}" -o "$ROOT/bin/guardrail" ./cmd/guardrail) \
        || die "the API build failed. Try: cd backend && go build ./..."
    info "bin/guardrail ready"
fi

# --- 7. browser isolation ---------------------------------------------------
# Reported, never installed. Isolation is how recorded and appliance-SPA devices
# are served, and a host without a browser must say so here rather than at
# Connect — which is what used to happen: the console advertised recording, an
# operator marked a device recorded on that promise, and only pressing Connect
# turned up "google-chrome: not found" as an HTTP 500.
step "Browser isolation (Chromium)"
# Under compose the API image installs Chromium itself (backend/Dockerfile) and
# pins GUARDRAIL_CHROME_PATH to it, and compose does not pass the host's value in.
# So the host's browser is not consulted, not needed, and not worth a warning that
# sends someone chasing `make deps` on a server that is already correct.
if [ "$NATIVE" -eq 0 ]; then
    info "in the API image ${D}(/usr/bin/chromium — the host's browser is not used)${N}"
else

chrome=""
if [ -n "${GUARDRAIL_CHROME_PATH:-}" ]; then
    if [ -x "${GUARDRAIL_CHROME_PATH}" ]; then
        chrome="${GUARDRAIL_CHROME_PATH} ${D}(pinned in .env)${N}"
    else
        warn "GUARDRAIL_CHROME_PATH=${GUARDRAIL_CHROME_PATH} is not executable — GuardRail will refuse it"
    fi
else
    for c in chromium chromium-browser google-chrome google-chrome-stable chrome; do
        p=$(command -v "$c" 2>/dev/null) && { chrome="$p"; break; }
    done
    # The same per-user caches the server itself falls back to.
    if [ -z "$chrome" ]; then
        cached=$(ls -d "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome \
                       "$HOME"/.cache/puppeteer/chrome/*/chrome-linux*/chrome 2>/dev/null | sort -r | head -1 || true)
        [ -n "$cached" ] && [ -x "$cached" ] && chrome="$cached ${D}(cached browser)${N}"
    fi
fi
if [ -n "$chrome" ]; then
    info "found: $chrome"
else
    warn "no Chromium found on this host."
    info "Devices set to isolated delivery will fall back to the reverse proxy,"
    info "and devices set to record sessions will be refused at Connect."
    info "To enable it:  ${B}make deps${N}   (then re-run this script)"
    info "${D}Not 'apt install chromium': Ubuntu ships no such deb, and"
    info "chromium-browser is a stub for the snap, whose confinement cannot read"
    info "the --user-data-dir we pass — installed, and still broken at Connect.${N}"
    info "Or drop --native: the compose API image ships its own Chromium."
fi

fi  # end of the --native-only host browser check

# --- 8. start ---------------------------------------------------------------
if [ "$NO_START" -eq 1 ]; then
    step "Set up, not started (--no-start)"
    info "start it with: ${B}scripts/bootstrap.sh${N}"
    exit 0
fi

port="${GUARDRAIL_HTTPS_PORT:-443}"
if [ "$NATIVE" -eq 1 ]; then
    step "Starting the API (native host process)"
    pkill -f "$ROOT/bin/guardrail" 2>/dev/null && info "stopped the previous instance" || true
    sleep 1
    GUARDRAIL_BIN="$ROOT/bin/guardrail" nohup "$ROOT/scripts/run-host-api.sh" >/tmp/guardrail.log 2>&1 &
    port=8080
    info "logs: /tmp/guardrail.log"
else
    step "Starting GuardRail"
    # --build is not an optimisation to skip: `api` and `frontend` are built
    # images, and plain `up -d` only builds when the image is ABSENT. On a server
    # that already ran this once, a re-run after new code applied the migrations
    # and then started the old binary against the new schema — which is the worst
    # of both, and looks like "the fix didn't work" rather than like a stale
    # image. This script's header promises a re-run deploys new code; this flag is
    # that promise. Layer caching makes it near-free when nothing changed.
    if [ "$SKIP_BUILD" -eq 1 ]; then
        docker compose up -d >/dev/null 2>&1 || die "docker compose up failed. Try: docker compose logs"
    else
        docker compose up -d --build >/dev/null 2>&1 || die "docker compose build/up failed. Try: docker compose up --build"
    fi
fi

# Poll the health endpoint rather than declaring success on exit status: a
# container that starts and then dies on a bad config still exits 0 here.
printf '    waiting for the API'
ok=0
for i in $(seq 1 60); do
    if curl -fsk "https://127.0.0.1:${port}/healthz" >/dev/null 2>&1 ||
       curl -fs  "http://127.0.0.1:${port}/healthz"  >/dev/null 2>&1; then
        ok=1; printf ' up\n'; break
    fi
    printf '.'; sleep 1
done
if [ "$ok" -eq 0 ]; then
    printf '\n'
    if [ "$NATIVE" -eq 1 ]; then
        warn "the API did not answer /healthz in 60s. Last lines of /tmp/guardrail.log:"
        tail -n 15 /tmp/guardrail.log 2>/dev/null | sed 's/^/      /'
    else
        warn "the API did not answer /healthz in 60s. Last lines of its log:"
        docker compose logs --tail=15 api 2>/dev/null | sed 's/^/      /'
    fi
    die "startup failed — see above"
fi

# --- done -------------------------------------------------------------------
host=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1]}')
host="${host:-localhost}"
cat <<EOF

${B}${G}GuardRail is up.${N}

  Console   ${B}https://${host}:${port}${N}
  Sign in   ${GUARDRAIL_ADMIN_EMAIL:-admin@guardrail.local}
  Password  in .env as GUARDRAIL_ADMIN_PASSWORD ${D}(change it after signing in)${N}

  ${D}The certificate is self-signed, so the browser will warn once.${N}

EOF
