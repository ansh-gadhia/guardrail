#!/usr/bin/env bash
#
# GuardRail installer — one file, run it on a clean server.
#
#   curl -fsSL https://raw.githubusercontent.com/ansh-gadhia/guardrail/main/scripts/install.sh | sudo bash
#   sudo ./install.sh
#
# It installs Docker if missing, asks for the handful of settings that cannot be
# guessed, writes them under /opt/guardrail, pulls the published images and
# starts the stack. Re-running it is safe: it detects what is already there and
# offers update / stop / remove instead of a second install.
#
# Design notes worth knowing before editing:
#
#   * Host-side files (compose file, Traefik config, migrations, seed SQL) are
#     fetched from the repository at the PINNED TAG, not from main. An installer
#     that pulls a v1.1.2 image next to a main-branch compose file is how a
#     deployment ends up in a combination nobody has ever tested.
#   * The .env is written once and preserved across updates. An update that
#     regenerated secrets would re-encrypt nothing and silently invalidate every
#     vaulted credential — the master key IS the vault.
#   * Everything runs under one compose project name, so detection and removal
#     are exact rather than pattern-matching container names.
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_NAME="GuardRail"
REPO="${GUARDRAIL_REPO:-ansh-gadhia/guardrail}"
VERSION="${GUARDRAIL_VERSION:-1.1.2}"
# Which git ref the host-side files come from. Images are published from main, so
# main is the default; set it to a tag or a commit to install a fixed point.
REF="${GUARDRAIL_REF:-main}"
INSTALL_DIR="${GUARDRAIL_DIR:-/opt/guardrail}"
PROJECT="guardrail"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Colours, dropped when stdout is not a terminal so logs stay readable.
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; MAG=$'\033[35m'
else
    R=""; B=""; D=""; RED=""; GRN=""; YLW=""; CYN=""; MAG=""
fi

info()  { printf '%s\n' "${CYN}  ▸${R} $*"; }
ok()    { printf '%s\n' "${GRN}  ✔${R} $*"; }
warn()  { printf '%s\n' "${YLW}  !${R} $*" >&2; }
err()   { printf '%s\n' "${RED}  ✘${R} $*" >&2; }
die()   { err "$*"; exit 1; }
step()  { printf '\n%s\n' "${B}$*${R}"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
banner() {
    local lines=(
'   ██████  ██    ██  █████  ██████  ██████   █████  ██ ██      '
'  ██       ██    ██ ██   ██ ██   ██ ██   ██ ██   ██ ██ ██      '
'  ██   ███ ██    ██ ███████ ██████  ██   ██ ███████ ██ ██      '
'  ██    ██ ██    ██ ██   ██ ██   ██ ██   ██ ██   ██ ██ ██      '
'   ██████   ██████  ██   ██ ██   ██ ██████  ██   ██ ██ ███████ '
    )
    clear 2>/dev/null || true
    printf '\n'
    # Animated only on a terminal: piped into a log, sleeping just makes the
    # install look hung.
    for l in "${lines[@]}"; do
        printf '%s\n' "${CYN}${B}${l}${R}"
        [ -t 1 ] && sleep 0.06
    done
    printf '\n'
    printf '%s\n' "        ${MAG}${B}Privileged Access Management${R}${D} · broker, record, audit${R}"
    printf '%s\n\n' "        ${D}v${VERSION} · ${REPO}${R}"
    [ -t 1 ] && sleep 0.15
    return 0
}

spin() {
    # Runs "$@" while showing a spinner; prints nothing extra when not a tty.
    local msg="$1"; shift
    if [ ! -t 1 ]; then
        printf '  ▸ %s\n' "$msg"
        "$@"
        return
    fi
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 rc=0
    local log; log=$(mktemp)
    "$@" >"$log" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i + 1) % ${#frames} ))
        printf '\r  %s %s' "${CYN}${frames:$i:1}${R}" "$msg"
        sleep 0.08
    done
    wait "$pid" || rc=$?
    if [ "$rc" -eq 0 ]; then
        printf '\r  %s %s\n' "${GRN}✔${R}" "$msg"
    else
        printf '\r  %s %s\n' "${RED}✘${R}" "$msg"
        sed 's/^/      /' "$log" >&2
    fi
    rm -f "$log"
    return "$rc"
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
need_root() {
    [ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
}

compose() {
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Answers are read from fd 3, not stdin.
#
# `curl ... | bash` leaves stdin holding the script itself, so prompts have to
# come from the terminal — but a run with no controlling terminal at all (CI, a
# cron job, a pipe under nohup) has no /dev/tty to open. Binding fd 3 once, here,
# makes every prompt work in all three cases, and a read that hits EOF aborts
# instead of re-prompting forever against a closed descriptor.
setup_input() {
    if exec 3</dev/tty 2>/dev/null; then
        return 0
    fi
    exec 3<&0
}

# read_input VAR [prompt] — returns non-zero at EOF.
read_input() {
    local __v="$1" __p="${2:-}" __a=""
    if [ -n "$__p" ]; then printf '%s' "$__p"; fi
    IFS= read -r -u 3 __a || return 1
    printf -v "$__v" '%s' "$__a"
}

read_secret() {
    local __v="$1" __p="${2:-}" __a=""
    if [ -n "$__p" ]; then printf '%s' "$__p"; fi
    IFS= read -r -s -u 3 __a || return 1
    echo
    printf -v "$__v" '%s' "$__a"
}

no_input() { die "no input available — run this from a terminal, or pipe answers in"; }

# Primary LAN address. Used for the TLS SAN, the console URL we print, and the
# address the bundled resolver hands out for the tunnel domain.
host_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'
}

# ---------------------------------------------------------------------------
# Detection: is GuardRail already on this box?
# ---------------------------------------------------------------------------
DETECTED=0
detect() {
    DETECTED=0
    local found_containers="" found_dir="" running=""

    if have docker; then
        found_containers=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
            --format '{{.Names}}\t{{.Status}}' 2>/dev/null || true)
        running=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" -q 2>/dev/null | wc -l | tr -d ' ')
    fi
    [ -d "$INSTALL_DIR" ] && found_dir=1

    if [ -n "$found_containers" ] || [ -n "$found_dir" ]; then
        DETECTED=1
        step "Existing ${APP_NAME} detected"
        [ -n "$found_dir" ] && info "install directory: ${B}${INSTALL_DIR}${R}"
        if [ -f "$ENV_FILE" ]; then
            local v hp sp
            v=$(grep -E '^VERSION=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
            sp=$(grep -E '^GUARDRAIL_HTTPS_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
            hp=$(grep -E '^GUARDRAIL_HTTP_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
            info "installed version: ${B}${v:-unknown}${R}   ports: ${B}https ${sp:-?}${R} / ${B}http ${hp:-?}${R}"
        fi
        if [ -n "$found_containers" ]; then
            info "containers (${running:-0} running):"
            printf '%s\n' "$found_containers" | while IFS=$'\t' read -r n s; do
                [ -z "$n" ] && continue
                case "$s" in
                    Up*) printf '      %s %-28s %s\n' "${GRN}●${R}" "$n" "${D}$s${R}" ;;
                    *)   printf '      %s %-28s %s\n' "${D}○${R}" "$n" "${D}$s${R}" ;;
                esac
            done
        fi
        # Anything of ours actually answering on the network, whatever the
        # configured port — the question asked is "is GuardRail running on this
        # server, on any port", so it is answered from what is bound, not from
        # what the .env claims.
        if have docker && [ "${running:-0}" -gt 0 ]; then
            local pub
            pub=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" \
                --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | grep -oE '0\.0\.0\.0:[0-9]+|:::[0-9]+' |
                grep -oE '[0-9]+$' | sort -un | tr '\n' ' ' || true)
            [ -n "$pub" ] && info "published ports: ${B}${pub}${R}"
        fi
    else
        step "No existing ${APP_NAME} on this server"
        info "nothing installed under ${INSTALL_DIR}, and no ${PROJECT} containers"
    fi
}

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
install_docker() {
    if have docker && docker compose version >/dev/null 2>&1; then
        ok "Docker and the compose plugin are present"
    else
        info "installing Docker (this can take a minute)"
        if have apt-get; then
            spin "apt-get update" env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            spin "installing prerequisites" env DEBIAN_FRONTEND=noninteractive \
                apt-get install -y -qq ca-certificates curl openssl
        elif have dnf; then
            spin "installing prerequisites" dnf install -y -q ca-certificates curl openssl
        elif have yum; then
            spin "installing prerequisites" yum install -y -q ca-certificates curl openssl
        fi
        # get.docker.com covers Debian/Ubuntu/RHEL/Fedora/SUSE and installs the
        # compose plugin with it. Preferred over distro packages, which on Ubuntu
        # LTS still ship a Docker too old for `docker compose`.
        spin "installing Docker Engine" bash -c 'curl -fsSL https://get.docker.com | sh'
        have docker || die "Docker installation failed"
        ok "Docker installed"
    fi

    # The stack's containers are restart: unless-stopped, so the only thing
    # standing between a reboot and a running GuardRail is the daemon itself
    # being enabled. Without this, a server comes back with nothing running.
    if have systemctl; then
        systemctl enable docker >/dev/null 2>&1 || true
        systemctl start docker >/dev/null 2>&1 || true
        if systemctl is-enabled docker >/dev/null 2>&1; then
            ok "Docker starts on boot — the stack comes back after a restart"
        else
            warn "could not enable docker at boot; GuardRail will not auto-start"
        fi
    fi

    have openssl || die "openssl is required and could not be installed"
}

# ---------------------------------------------------------------------------
# Fetching the host-side files
# ---------------------------------------------------------------------------
# The images come from GHCR; these are the files the stack mounts from the host:
# the compose file, Traefik's dynamic config, the Postgres bootstrap script, the
# migrations and the seed SQL.
fetch_release() {
    local src_root=""
    # Running from inside a checkout (developer, or an air-gapped copy) uses the
    # local tree, so the installer is testable without a tagged release.
    if [ -f "$(dirname "${BASH_SOURCE[0]}")/../docker-compose.yml" ]; then
        src_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
        info "using the checkout at ${D}${src_root}${R}"
    fi

    mkdir -p "$INSTALL_DIR"
    if [ -n "$src_root" ]; then
        cp "$src_root/docker-compose.yml" "$COMPOSE_FILE"
        mkdir -p "$INSTALL_DIR/deploy" "$INSTALL_DIR/backend"
        cp -r "$src_root/deploy/traefik" "$INSTALL_DIR/deploy/"
        cp -r "$src_root/deploy/postgres" "$INSTALL_DIR/deploy/"
        cp -r "$src_root/backend/migrations" "$INSTALL_DIR/backend/"
        mkdir -p "$INSTALL_DIR/backend/db"
        cp "$src_root/backend/db/seed.sql" "$INSTALL_DIR/backend/db/seed.sql"
    else
        local tmp; tmp=$(mktemp -d)
        # Images are published from main, so the host-side files come from a
        # branch by default. A tag or commit works too: heads is tried first,
        # then tags, so GUARDRAIL_REF takes either without the caller having to
        # say which kind it is.
        local ok=0
        for kind in heads tags; do
            local url="https://codeload.github.com/${REPO}/tar.gz/refs/${kind}/${REF}"
            if curl -fsSL "$url" 2>/dev/null | tar xz -C "$tmp" --strip-components=1 2>/dev/null; then
                ok=1
                info "host files from ${B}${REF}${R} ${D}(${kind})${R}"
                break
            fi
        done
        [ "$ok" = "1" ] || die "could not download ${REPO} at ref '${REF}' — check it exists and the network is up"
        cp "$tmp/docker-compose.yml" "$COMPOSE_FILE"
        mkdir -p "$INSTALL_DIR/deploy" "$INSTALL_DIR/backend/db"
        cp -r "$tmp/deploy/traefik" "$INSTALL_DIR/deploy/"
        cp -r "$tmp/deploy/postgres" "$INSTALL_DIR/deploy/"
        cp -r "$tmp/backend/migrations" "$INSTALL_DIR/backend/"
        cp "$tmp/backend/db/seed.sql" "$INSTALL_DIR/backend/db/seed.sql"
        rm -rf "$tmp"
    fi
    ok "host files in place"
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
ask() { # ask VAR "Prompt" "default"
    local __var="$1" __prompt="$2" __default="${3:-}" __ans=""
    if [ -n "$__default" ]; then
        read_input __ans "  ${__prompt} ${D}[${__default}]${R}: " || no_input
        __ans="${__ans:-$__default}"
    else
        while [ -z "$__ans" ]; do
            read_input __ans "  ${__prompt}: " || no_input
        done
    fi
    printf -v "$__var" '%s' "$__ans"
}

ask_yn() { # ask_yn VAR "Prompt" "y|n"
    local __var="$1" __prompt="$2" __default="${3:-y}" __ans=""
    local hint="[Y/n]"; [ "$__default" = "n" ] && hint="[y/N]"
    while true; do
        read_input __ans "  ${__prompt} ${D}${hint}${R}: " || no_input
        __ans="${__ans:-$__default}"
        case "${__ans,,}" in
            y|yes) printf -v "$__var" '%s' "yes"; return 0 ;;
            n|no)  printf -v "$__var" '%s' "no";  return 0 ;;
            *) warn "answer y or n" ;;
        esac
    done
}

ask_port() { # ask_port VAR "Prompt" default
    local __var="$1" __prompt="$2" __default="$3" __ans=""
    while true; do
        ask __ans "$__prompt" "$__default"
        if [[ "$__ans" =~ ^[0-9]+$ ]] && [ "$__ans" -ge 1 ] && [ "$__ans" -le 65535 ]; then
            # A port already in use by something else fails at `up` with an error
            # nobody reads; catching it here costs one line and saves the call.
            if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${__ans}\$"; then
                if [ "${DETECTED}" = "1" ]; then
                    # Our own stack may well be holding it right now.
                    printf -v "$__var" '%s' "$__ans"; return 0
                fi
                warn "port ${__ans} is already in use on this server"
                continue
            fi
            printf -v "$__var" '%s' "$__ans"; return 0
        fi
        warn "enter a port between 1 and 65535"
    done
}

ask_password() { # ask_password VAR
    local __var="$1" a="" b=""
    while true; do
        read_secret a "  Admin password ${D}(min 12 chars)${R}: " || no_input
        if [ "${#a}" -lt 12 ]; then
            # Not an arbitrary rule: the API refuses to start if this is set and
            # shorter than 12, so accepting one here would produce an install
            # that fails at boot with a message the operator never sees.
            warn "too short — the server refuses to start with fewer than 12 characters"
            continue
        fi
        read_secret b "  Confirm password: " || no_input
        [ "$a" = "$b" ] && { printf -v "$__var" '%s' "$a"; return 0; }
        warn "passwords did not match"
    done
}

secret() { openssl rand -base64 48 | tr -d '\n'; }

# ---------------------------------------------------------------------------
# The DNS question, asked on install AND update
# ---------------------------------------------------------------------------
# Whole-host session delivery serves each session at <session-id>.<domain>, which
# needs a wildcard DNS record. The bundled resolver provides one; a site with its
# own DNS may prefer to add the record there instead. It is re-asked on update
# because it is the setting most likely to change after the fact — a lab turns it
# on, an enterprise turns it off once their own resolver has the record.
configure_dns() {
    local current_domain="${1:-tunnel.guardrail.lan}" current_enabled="${2:-yes}"
    step "Session tunnel and DNS"
    printf '%s\n' "  ${D}Brokered web sessions can be served at their own hostname"
    printf '%s\n' "  (<session-id>.<domain>) instead of under a /proxy/ path. Appliance"
    printf '%s\n' "  UIs that hard-navigate need this. It requires wildcard DNS.${R}"
    echo
    ask_yn DNS_ENABLED "Run the bundled DNS resolver for the tunnel domain?" "$([ "$current_enabled" = "yes" ] && echo y || echo n)"
    if [ "$DNS_ENABLED" = "yes" ]; then
        ask TUNNEL_DOMAIN "Tunnel domain" "$current_domain"
        ask DNS_UPSTREAM "Upstream DNS for everything else" "${GUARDRAIL_DNS_UPSTREAM:-8.8.8.8}"
        info "the resolver will answer ${B}*.${TUNNEL_DOMAIN}${R} with ${B}$(host_ip)${R}"
        info "point your clients' primary DNS at ${B}$(host_ip)${R} to use it"
    else
        # Empty domain disables the tunnel entirely; sessions fall back to the
        # path-prefixed proxy, which is exactly how it worked before it existed.
        ask_yn KEEP_TUNNEL "Keep the tunnel enabled anyway (you provide the wildcard record)?" n
        if [ "$KEEP_TUNNEL" = "yes" ]; then
            ask TUNNEL_DOMAIN "Tunnel domain" "$current_domain"
            warn "add this record on your resolver: *.${TUNNEL_DOMAIN} -> $(host_ip)"
        else
            TUNNEL_DOMAIN=""
            info "tunnel disabled — sessions serve under /proxy/<id>/"
        fi
        DNS_UPSTREAM="${GUARDRAIL_DNS_UPSTREAM:-8.8.8.8}"
    fi
}

# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
generate_cert() {
    local tls="$INSTALL_DIR/deploy/tls"
    mkdir -p "$tls"
    local sans="DNS:localhost,IP:127.0.0.1"
    local ip; ip=$(host_ip)
    [ -n "$ip" ] && sans="$sans,IP:$ip"
    [ -n "${TUNNEL_DOMAIN:-}" ] && sans="$sans,DNS:*.${TUNNEL_DOMAIN},DNS:${TUNNEL_DOMAIN}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$tls/key.pem" -out "$tls/cert.pem" \
        -subj "/CN=guardrail" -addext "subjectAltName=$sans" >/dev/null 2>&1 \
        || die "openssl could not generate a certificate"
    chmod 600 "$tls/key.pem"
    ok "self-signed certificate for ${D}${sans}${R}"
}

# ---------------------------------------------------------------------------
# Writing .env
# ---------------------------------------------------------------------------
write_env() {
    local ip; ip=$(host_ip)
    umask 077
    cat >"$ENV_FILE" <<EOF
# GuardRail — generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Secrets in this file are the only copy. GUARDRAIL_MASTER_KEY decrypts the
# credential vault: lose it and every stored device credential is unrecoverable.
# Back this file up somewhere other than this server.

GUARDRAIL_ENV=production
VERSION=${VERSION}

# ---- Published ports ----
GUARDRAIL_HTTPS_PORT=${HTTPS_PORT}
GUARDRAIL_HTTP_PORT=${HTTP_PORT}
POSTGRES_BIND_ADDR=127.0.0.1
POSTGRES_PORT=5432
REDIS_BIND_ADDR=127.0.0.1
REDIS_PORT=6379

# ---- HTTP ----
GUARDRAIL_TRUST_PROXY_HEADERS=true
GUARDRAIL_TRUSTED_PROXIES=0.0.0.0/0
GUARDRAIL_CORS_ALLOW_ORIGINS=

# ---- Session tunnel ----
GUARDRAIL_TUNNEL_DOMAIN=${TUNNEL_DOMAIN}
GUARDRAIL_DNS_UPSTREAM=${DNS_UPSTREAM}

# ---- Secrets ----
GUARDRAIL_JWT_SIGNING_KEY=${JWT_KEY}
GUARDRAIL_MASTER_KEY=${MASTER_KEY}

# ---- PostgreSQL ----
POSTGRES_USER=guardrail
POSTGRES_PASSWORD=${PG_PASSWORD}
POSTGRES_DB=guardrail
GUARDRAIL_DB_APP_PASSWORD=${PG_APP_PASSWORD}

# ---- Redis ----
REDIS_PASSWORD=

# ---- Primary super admin (seeded on first boot) ----
GUARDRAIL_ADMIN_EMAIL=${ADMIN_EMAIL}
GUARDRAIL_ADMIN_PASSWORD=${ADMIN_PASSWORD}
GUARDRAIL_ADMIN_USERNAME=admin
GUARDRAIL_ADMIN_ORG=default

# ---- Session recording ----
GUARDRAIL_BROWSER_ISOLATION=true
GUARDRAIL_CHROME_PATH=
GUARDRAIL_RECORDING_DIR=/var/lib/guardrail/recordings

# ---- Desktop access (RDP / VNC) ----
GUARDRAIL_DESKTOP_ENABLED=${DESKTOP_ENABLED}
GUARDRAIL_GUACD_RECORDING_DIR=/var/lib/guardrail/desktop-recordings

# ---- Logging ----
GUARDRAIL_LOG_LEVEL=info
GUARDRAIL_LOG_FORMAT=json
EOF
    chmod 600 "$ENV_FILE"
    ok "configuration written to ${B}${ENV_FILE}${R} ${D}(mode 600)${R}"
    [ -n "$ip" ] && info "server address detected as ${B}${ip}${R}"
}

# guacd writes desktop recordings as uid 1000 and the API reads them back
# through a shared group. Docker would otherwise create this path root:root 755,
# which guacd cannot write to — and it does not fail loudly when that happens:
# the session records nothing and says so only in a log line.
prepare_dirs() {
    local d=/var/lib/guardrail/desktop-recordings
    mkdir -p "$d"
    chown 1000:1000 "$d" 2>/dev/null || true
    chmod 2770 "$d" 2>/dev/null || true
}

profiles() {
    local p=()
    [ "${DNS_ENABLED:-no}" = "yes" ] && p+=(--profile dns)
    [ "${DESKTOP_ENABLED:-true}" = "true" ] && p+=(--profile desktop)
    printf '%s\n' "${p[@]}"
}

start_stack() {
    local -a prof=()
    mapfile -t prof < <(profiles)
    step "Starting ${APP_NAME}"
    spin "pulling images (${VERSION})" \
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${prof[@]}" pull --quiet \
        || warn "some images could not be pulled; falling back to whatever is local"
    spin "starting services" \
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${prof[@]}" up -d --remove-orphans
}

wait_healthy() {
    local tries=60
    printf '  %s waiting for the API to answer' "${CYN}⠿${R}"
    while [ "$tries" -gt 0 ]; do
        if curl -fsk --max-time 3 "https://127.0.0.1:${HTTPS_PORT}/healthz" >/dev/null 2>&1; then
            printf '\r'; ok "API is healthy                        "
            return 0
        fi
        printf '.'
        sleep 2
        tries=$((tries - 1))
    done
    printf '\r'
    warn "the API did not become healthy in time — check: docker compose -p $PROJECT logs api"
    return 0
}

summary() {
    local ip; ip=$(host_ip)
    step "${APP_NAME} is running"
    printf '\n'
    printf '    %s  %s\n' "${B}Console${R}" "https://${ip:-127.0.0.1}${HTTPS_PORT:+:$HTTPS_PORT}"
    printf '    %s    %s\n' "${B}Admin${R}" "${ADMIN_EMAIL:-$(grep -E '^GUARDRAIL_ADMIN_EMAIL=' "$ENV_FILE" | cut -d= -f2-)}"
    printf '    %s   %s\n' "${B}Config${R}" "$ENV_FILE"
    if [ "${DNS_ENABLED:-no}" = "yes" ]; then
        printf '    %s      %s\n' "${B}DNS${R}" "point clients at ${ip} for *.${TUNNEL_DOMAIN}"
    fi
    printf '\n'
    printf '  %s\n' "${D}The certificate is self-signed: your browser will warn once.${R}"
    printf '  %s\n' "${D}Change the admin password after first sign-in (Account → Password).${R}"
    printf '  %s\n\n' "${D}Manage: sudo $0${R}"
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
do_install() {
    if [ -f "$ENV_FILE" ]; then
        warn "a configuration already exists at $ENV_FILE"
        ask_yn OVERWRITE "Reinstall and OVERWRITE it? Existing data volumes are kept" n
        [ "$OVERWRITE" = "yes" ] || { info "left alone"; return 0; }
    fi

    step "Configuration"
    ask_port HTTPS_PORT "HTTPS port (console, API and sessions)" 443
    ask_port HTTP_PORT  "HTTP port (redirects to HTTPS)" 80
    ask ADMIN_EMAIL "Admin email" "admin@example.com"
    ask_password ADMIN_PASSWORD
    ask_yn DESKTOP_YN "Enable desktop access (RDP/VNC via guacd)?" y
    DESKTOP_ENABLED=$([ "$DESKTOP_YN" = "yes" ] && echo true || echo false)

    configure_dns "tunnel.guardrail.lan" "yes"

    JWT_KEY=$(secret); MASTER_KEY=$(secret)
    PG_PASSWORD=$(secret | tr -d '/+=' | cut -c1-32)
    PG_APP_PASSWORD=$(secret | tr -d '/+=' | cut -c1-32)

    step "Installing"
    install_docker
    fetch_release
    prepare_dirs
    write_env
    generate_cert
    start_stack
    wait_healthy
    summary
}

do_update() {
    [ -f "$ENV_FILE" ] || die "nothing to update — no $ENV_FILE. Run install first."

    # Read what is already configured so the update keeps it.
    local cur_domain cur_dns
    cur_domain=$(grep -E '^GUARDRAIL_TUNNEL_DOMAIN=' "$ENV_FILE" | cut -d= -f2- || true)
    HTTPS_PORT=$(grep -E '^GUARDRAIL_HTTPS_PORT=' "$ENV_FILE" | cut -d= -f2- || echo 443)
    DESKTOP_ENABLED=$(grep -E '^GUARDRAIL_DESKTOP_ENABLED=' "$ENV_FILE" | cut -d= -f2- || echo true)
    if docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null | grep -q -- '-dns-'; then
        cur_dns=yes
    else
        cur_dns=no
    fi

    step "Update"
    ask NEW_VERSION "Version to install" "$VERSION"
    VERSION="$NEW_VERSION"

    # Re-asked on every update, deliberately: this is the setting most likely to
    # change after the initial install, and burying it would mean editing .env by
    # hand — which is exactly what an installer exists to avoid.
    configure_dns "${cur_domain:-tunnel.guardrail.lan}" "$cur_dns"

    install_docker
    fetch_release

    # Rewrite only the keys this update owns. The secrets, the admin credential
    # and the database passwords are left untouched: regenerating the master key
    # would orphan every credential in the vault.
    sed -i \
        -e "s|^VERSION=.*|VERSION=${VERSION}|" \
        -e "s|^GUARDRAIL_TUNNEL_DOMAIN=.*|GUARDRAIL_TUNNEL_DOMAIN=${TUNNEL_DOMAIN}|" \
        -e "s|^GUARDRAIL_DNS_UPSTREAM=.*|GUARDRAIL_DNS_UPSTREAM=${DNS_UPSTREAM}|" \
        "$ENV_FILE"
    grep -q '^GUARDRAIL_DNS_UPSTREAM=' "$ENV_FILE" || echo "GUARDRAIL_DNS_UPSTREAM=${DNS_UPSTREAM}" >>"$ENV_FILE"
    ok "configuration updated (secrets and admin credentials untouched)"

    # The cert has to name the tunnel domain, which may have just changed.
    generate_cert
    prepare_dirs

    # A DNS resolver that was on and is now off has to be removed, not just left
    # out of the next `up` — compose would otherwise leave it running forever.
    if [ "${DNS_ENABLED}" = "no" ]; then
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" --profile dns rm -sf dns >/dev/null 2>&1 || true
        info "bundled DNS resolver stopped and removed"
    fi

    start_stack
    # Traefik loads certificates at startup and does not watch the file, so a
    # regenerated cert is invisible to it until it is restarted. Skipping this is
    # how a server ends up serving a certificate for an address it no longer has.
    spin "reloading the edge certificate" docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" restart traefik
    wait_healthy
    summary
}

do_stop() {
    [ -f "$COMPOSE_FILE" ] || die "nothing to stop — no $COMPOSE_FILE"
    step "Stopping ${APP_NAME}"
    spin "stopping containers" docker compose -p "$PROJECT" --env-file "$ENV_FILE" \
        -f "$COMPOSE_FILE" --profile dns --profile desktop stop
    ok "stopped — data is untouched; start it again with the update option"
}

do_remove() {
    step "Remove ${APP_NAME} completely"
    warn "this deletes the containers, the images, the DATABASE, the credential"
    warn "vault and every session recording. It cannot be undone."
    echo
    local confirm=""
    read_input confirm "  Type ${B}REMOVE${R} to confirm: " || no_input
    [ "$confirm" = "REMOVE" ] || { info "cancelled — nothing was removed"; return 0; }

    if [ -f "$COMPOSE_FILE" ]; then
        # -v takes the named volumes with it; without it the database survives and
        # a later install silently adopts an old vault it has no key for.
        spin "removing containers and volumes" bash -c \
            "docker compose -p '$PROJECT' --env-file '$ENV_FILE' -f '$COMPOSE_FILE' --profile dns --profile desktop down -v --remove-orphans" \
            || true
    fi
    # Sweep anything left over from an interrupted run, by project label.
    if have docker; then
        local leftovers
        leftovers=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)
        [ -n "$leftovers" ] && docker rm -f $leftovers >/dev/null 2>&1 || true
        spin "removing images" bash -c \
            "docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'guardrail' | xargs -r docker rmi -f" || true
    fi

    rm -rf "$INSTALL_DIR"
    rm -rf /var/lib/guardrail
    ok "removed: containers, volumes, images, ${INSTALL_DIR} and /var/lib/guardrail"
    info "Docker itself was left installed"
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
menu() {
    while true; do
        step "What would you like to do?"
        printf '    %s  Install %s\n'  "${B}1${R}" "${D}(fresh setup on this server)${R}"
        printf '    %s  Update %s\n'   "${B}2${R}" "${D}(pull a newer version, re-ask DNS settings)${R}"
        printf '    %s  Stop %s\n'     "${B}3${R}" "${D}(stop the stack, keep all data)${R}"
        printf '    %s  Remove %s\n'   "${B}4${R}" "${D}(delete everything, irreversible)${R}"
        printf '    %s  Exit\n\n'      "${B}5${R}"
        local choice=""
        read_input choice "  Choice [1-5]: " || no_input
        case "$choice" in
            1) do_install; return 0 ;;
            2) do_update;  return 0 ;;
            3) do_stop;    return 0 ;;
            4) do_remove;  return 0 ;;
            5) info "nothing changed"; return 0 ;;
            *) warn "pick a number from 1 to 5" ;;
        esac
    done
}

main() {
    need_root
    setup_input
    banner
    detect
    menu
}

main "$@"
