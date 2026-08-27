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
VERSION="${GUARDRAIL_VERSION:-1.2.0}"
# Which git ref the host-side files come from. Images are published from main, so
# main is the default; set it to a tag or a commit to install a fixed point.
REF="${GUARDRAIL_REF:-main}"
INSTALL_DIR="${GUARDRAIL_DIR:-/opt/guardrail}"
# Compose project name. Everything — containers, network and NAMED VOLUMES — is
# scoped by it, so overriding it gives a completely separate instance on the same
# host. That is the supported way to try a build alongside a live deployment:
#   GUARDRAIL_PROJECT=guardrail-test GUARDRAIL_DIR=/opt/guardrail-test ./install.sh
PROJECT="${GUARDRAIL_PROJECT:-guardrail}"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Colours, dropped when stdout is not a terminal so logs stay readable.
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'
else
    R=""; B=""; D=""; RED=""; GRN=""; YLW=""; CYN=""
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
#
# The wordmark is drawn with '#' rather than with block characters directly, and
# translated at print time. Two reasons, both of which bit the previous version:
#
#   * `${#l}` and `${l:i:1}` count BYTES under a C/POSIX locale, and a block
#     glyph is three bytes. Slicing one apart mid-character prints mojibake and
#     throws the per-column gradient out of alignment — on exactly the kind of
#     bare server this script is meant for, where no locale is set.
#   * A terminal that cannot render U+2588 gets a clean ASCII wordmark instead of
#     a field of question marks.
#
# It also makes a misspelling visible in review. The old art read GUARDAIL: five
# rows of block glyphs, one missing letter, and nobody spotted it until it had
# been printed on every install.
GR_WORDMARK=(
' #### #   #  ###  ####  ####  ####   ###  ##### #    '
'#     #   # #   # #   # #   # #   # #   #   #   #    '
'#  ## #   # ##### ####  #   # ####  #####   #   #    '
'#   # #   # #   # #  #  #   # #  #  #   #   #   #    '
' ####  ###  #   # #   # ####  #   # #   # ##### #####'
)

# True colour, only where the terminal says it has it.
gr_truecolor() {
    [ -t 1 ] || return 1
    case "${COLORTERM:-}" in truecolor | 24bit) return 0 ;; esac
    return 1
}

banner() {
    local block='#'
    case "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" in
        *UTF-8* | *utf-8* | *UTF8* | *utf8*) block=$'█' ;;
    esac

    clear 2>/dev/null || true
    printf '\n'

    local w=${#GR_WORDMARK[0]} i ch line out
    # Per-column colour ramp: teal through to indigo, the console's own accent
    # sweeping left to right. Computed once, reused for all five rows, so the
    # colour reads as a single vertical curtain rather than five stripes.
    local -a ramp=()
    if gr_truecolor; then
        local r g b
        for ((i = 0; i < w; i++)); do
            r=$((45 + (129 - 45) * i / (w - 1)))
            g=$((212 + (140 - 212) * i / (w - 1)))
            b=$((191 + (248 - 191) * i / (w - 1)))
            ramp[i]=$'\033[38;2;'"${r};${g};${b}"'m'
        done
    fi

    for line in "${GR_WORDMARK[@]}"; do
        out=""
        for ((i = 0; i < ${#line}; i++)); do
            ch=${line:i:1}
            if [ "$ch" = " " ]; then
                out+=" "
            elif [ ${#ramp[@]} -gt 0 ]; then
                out+="${ramp[i]}${block}"
            else
                out+="${CYN}${B}${block}"
            fi
        done
        printf '   %s%s\n' "$out" "$R"
        # Animated only on a terminal: piped into a log, sleeping just makes the
        # install look hung.
        [ -t 1 ] && sleep 0.05
    done

    # A hairline the exact width of the wordmark, carrying the tagline. The rule
    # is the only decoration; the colour ramp is the one indulgence.
    #
    # Separators follow the same ASCII/UTF-8 fork as the wordmark. A middot is
    # multibyte too, so hardcoding one would reintroduce the mojibake the block
    # character was just spared.
    local rule="" dash="-" dot="-"
    if [ "$block" != "#" ]; then dash=$'─' dot=$'·'; fi
    for ((i = 0; i < w; i++)); do rule+="$dash"; done
    printf '   %s\n' "${D}${rule}${R}"
    printf '   %s\n' "${B}Privileged Access Management${R}${D}  ${dot}  broker ${dot} record ${dot} audit${R}"
    printf '   %s\n\n' "${D}v${VERSION} ${dot} ${REPO}${R}"
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
    local __ri_v="$1" __ri_p="${2:-}" __ri_a=""
    if [ -n "$__ri_p" ]; then printf '%s' "$__ri_p"; fi
    IFS= read -r -u 3 __ri_a || return 1
    printf -v "$__ri_v" '%s' "$__ri_a"
}

read_secret() {
    local __rs_v="$1" __rs_p="${2:-}" __rs_a=""
    if [ -n "$__rs_p" ]; then printf '%s' "$__rs_p"; fi
    IFS= read -r -s -u 3 __rs_a || return 1
    echo
    printf -v "$__rs_v" '%s' "$__rs_a"
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
            local pgm
            pgm=$(grep -E '^GUARDRAIL_PGDATA_MOUNT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
            if [ -n "$pgm" ]; then
                info "data directory: ${B}$(dirname "$pgm")${R}"
            else
                info "data: ${B}Docker volumes${R} ${D}(/var/lib/docker/volumes/${PROJECT}_*)${R}"
            fi
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

# data_volumes lists this project's persistent volumes that already exist.
#
# These outlive `compose down` and are scoped by project name, so a stack started
# from a git checkout in ~/guardrail owns exactly the same volumes an install
# under /opt/guardrail would adopt.
data_volumes() {
    have docker || return 0
    docker volume ls --format '{{.Name}}' 2>/dev/null |
        grep -E "^${PROJECT}_(pgdata|recordings|desktop-recordings|redisdata)$" || true
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
# Operator-facing scripts that ship next to the compose file, so that a server
# installed by `curl | bash` — with no checkout anywhere on it — still has them.
# Absent from an older ref, which is not an error: the installer's own job does
# not depend on them.
install_helper() {
    [ -f "$1" ] || return 0
    cp "$1" "$INSTALL_DIR/$(basename "$1")"
    chmod 755 "$INSTALL_DIR/$(basename "$1")"
}

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
        install_helper "$src_root/scripts/migrate-data.sh"
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
        install_helper "$tmp/scripts/migrate-data.sh"
        rm -rf "$tmp"
    fi
    ok "host files in place"
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
# These write their answer into a caller-named variable, which makes shadowing a
# real hazard: a helper whose local happens to share a name with the variable it
# was asked to fill assigns to ITS OWN copy, the caller sees nothing, and a
# validation loop spins forever. That is exactly what ask_port -> ask did when
# both used "__ans".
#
# So each function's internals carry ITS OWN prefix — __ask_, __yn_, __port_,
# __pw_, __ri_, __rs_. A caller passes either a user-level name or one of its own
# __<self>_ names, and a callee only ever declares __<callee>_ names, so the two
# cannot collide by construction. A shared prefix would NOT have been enough:
# that just moves the collision, which is how the first fix failed.
ask() { # ask VAR "Prompt" "default"
    local __ask_var="$1" __ask_prompt="$2" __ask_default="${3:-}" __ask_ans=""
    if [ -n "$__ask_default" ]; then
        read_input __ask_ans "  ${__ask_prompt} ${D}[${__ask_default}]${R}: " || no_input
        __ask_ans="${__ask_ans:-$__ask_default}"
    else
        while [ -z "$__ask_ans" ]; do
            read_input __ask_ans "  ${__ask_prompt}: " || no_input
        done
    fi
    printf -v "$__ask_var" '%s' "$__ask_ans"
}

# ask_optional VAR "Prompt" — blank is a legitimate answer, so unlike ask() this
# does not loop until something is typed. For settings where "nothing" means
# "keep doing what you have always done".
ask_optional() { # ask_optional VAR "Prompt"
    local __opt_var="$1" __opt_prompt="$2" __opt_ans=""
    read_input __opt_ans "  ${__opt_prompt}: " || no_input
    printf -v "$__opt_var" '%s' "$__opt_ans"
}

ask_yn() { # ask_yn VAR "Prompt" "y|n"
    local __yn_var="$1" __yn_prompt="$2" __yn_default="${3:-y}" __yn_ans=""
    local __yn_hint="[Y/n]"; [ "$__yn_default" = "n" ] && __yn_hint="[y/N]"
    while true; do
        read_input __yn_ans "  ${__yn_prompt} ${D}${__yn_hint}${R}: " || no_input
        __yn_ans="${__yn_ans:-$__yn_default}"
        case "${__yn_ans,,}" in
            y|yes) printf -v "$__yn_var" '%s' "yes"; return 0 ;;
            n|no)  printf -v "$__yn_var" '%s' "no";  return 0 ;;
            *) warn "answer y or n" ;;
        esac
    done
}

ask_port() { # ask_port VAR "Prompt" default
    local __port_var="$1" __port_prompt="$2" __port_default="$3" __port_ans="" __port_reuse=""
    while true; do
        ask __port_ans "$__port_prompt" "$__port_default"
        if [[ "$__port_ans" =~ ^[0-9]+$ ]] && [ "$__port_ans" -ge 1 ] && [ "$__port_ans" -le 65535 ]; then
            # A port already in use fails at `up` with an error nobody reads.
            #
            # "Something is already installed" is NOT proof the port is ours: a
            # second, isolated instance under a different project collides with
            # the first exactly here. So ask instead of assuming — an operator
            # re-running the installer against their own stack answers yes, and
            # anyone else finds out now rather than after the config is written.
            if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${__port_ans}\$"; then
                warn "port ${__port_ans} is already in use on this server"
                ask_yn __port_reuse "Use it anyway (only if it is this GuardRail holding it)?" n
                [ "$__port_reuse" = "yes" ] || continue
            fi
            printf -v "$__port_var" '%s' "$__port_ans"; return 0
        fi
        warn "enter a port between 1 and 65535"
    done
}

ask_password() { # ask_password VAR
    local __pw_var="$1" __pw_a="" __pw_b=""
    while true; do
        read_secret __pw_a "  Admin password ${D}(min 12 chars)${R}: " || no_input
        if [ "${#__pw_a}" -lt 12 ]; then
            # Not an arbitrary rule: the API refuses to start if this is set and
            # shorter than 12, so accepting one here would produce an install
            # that fails at boot with a message the operator never sees.
            warn "too short — the server refuses to start with fewer than 12 characters"
            continue
        fi
        read_secret __pw_b "  Confirm password: " || no_input
        [ "$__pw_a" = "$__pw_b" ] && { printf -v "$__pw_var" '%s' "$__pw_a"; return 0; }
        warn "passwords did not match"
    done
}

secret() { openssl rand -base64 48 | tr -d '\n'; }

# port_free reports whether nothing is listening on a port.
port_free() {
    ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${1}\$"
}

# free_port returns the preferred port, or the next free one above it.
#
# Postgres, Redis and guacd are published on loopback for psql, backups and
# debugging — useful, and not something worth adding three prompts for. But the
# defaults are fixed, so a SECOND instance on the same host collided on 5432
# before it had started a single container, with a daemon error rather than
# anything an operator could act on. Shifting quietly and saying so is better
# than either failing or interrogating everyone about ports they do not care
# about.
free_port() {
    local want="$1" p="$1" limit=$(( $1 + 50 ))
    while [ "$p" -le "$limit" ]; do
        if port_free "$p"; then printf '%s' "$p"; return 0; fi
        p=$(( p + 1 ))
    done
    printf '%s' "$want"
}

# note_port reports a shift. Kept OUT of free_port deliberately: free_port's
# stdout IS its return value, so anything it printed for a human was captured
# into the variable instead — the .env ended up with the whole notice where the
# port should be, and compose refused it as "invalid hostPort".
note_port() {
    [ "$2" = "$3" ] || info "$1 port $2 is taken; using ${B}$3${R} for this instance"
}

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
    # Where a pinned SIEM certificate goes, if single sign-on is wired up later.
    # Created empty on every install so the compose bind mount always has a real
    # directory to point at, and so an operator adding SSO afterwards has an
    # obvious place to drop the file rather than inventing one.
    mkdir -p "$INSTALL_DIR/deploy/siem"
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

# ensure_env_key adds a setting to an existing .env if it is not already there,
# leaving any value the operator has already chosen alone.
#
# An update rewrites only the keys it owns and must never regenerate secrets, so
# it cannot simply re-run write_env. That leaves a gap every time a release adds
# a setting: the deployment keeps running on the compose file's fallback, and the
# key is missing from the one file an operator would look in. Keys added by a
# release are listed in migrate_env below.
ensure_env_key() {
    local key=$1 value=$2 comment=${3:-}
    grep -qE "^${key}=" "$ENV_FILE" && return 0
    {
        printf '\n'
        [ -n "$comment" ] && printf '# %s\n' "$comment"
        printf '%s=%s\n' "$key" "$value"
    } >>"$ENV_FILE"
    info "added ${B}${key}${R} to the configuration ${D}(default: ${value:-blank})${R}"
}

# migrate_env brings an older .env up to what this release expects. Add a line
# here for every setting a release introduces; it is a no-op on a file that
# already has it, so it is safe to leave in place across releases.
migrate_env() {
    ensure_env_key GUARDRAIL_RECORDING_RETENTION_DAYS 90 \
        "How long recordings are kept, in days (0 = indefinitely). Seeds an organization that has never set its own policy; the console (Organization -> Recording retention) is what is in force once one has."
    # Added blank on purpose: an existing deployment's data is in the named
    # volumes, and blank is what keeps it there. Writing a path here would
    # repoint a running install at an empty directory. scripts/migrate-data.sh
    # is what fills these in, after it has moved the data.
    ensure_env_key GUARDRAIL_PGDATA_MOUNT "" \
        "Where the data lives. Blank = Docker-managed named volumes; an absolute path = that path, bind-mounted. Do not repoint these by hand on a running deployment — scripts/migrate-data.sh moves the data and rewrites them together."
    ensure_env_key GUARDRAIL_RECORDINGS_MOUNT ""
    ensure_env_key GUARDRAIL_REDIS_MOUNT ""
    # SIEM single sign-on. All blank or defaulted, so an existing deployment is
    # unchanged by the upgrade: SSO stays off until somebody fills in the JWKS
    # URL and the organization, and every other key here reproduces the
    # behaviour of a deployment that has never heard of the SIEM.
    ensure_env_key GUARDRAIL_FEDERATION_ORG_ID "" \
        "The organization federated users (OIDC, LDAP, SIEM SSO) are provisioned into. Blank leaves every federated provider off."
    ensure_env_key GUARDRAIL_SIEM_JWKS_URL "" \
        "SIEM single sign-on — see docs/SIEM_SSO.md. HTTPS URL where the SIEM publishes its public keys; setting this and the organization above turns the feature on."
    ensure_env_key GUARDRAIL_SIEM_JWKS_CA_BUNDLE "" \
        "The SIEM's own TLS certificate, so the key fetch is pinned to it. Drop the PEM in deploy/siem/ and name its in-container path here, e.g. /etc/guardrail/siem/jwks-ca.pem."
    ensure_env_key GUARDRAIL_SIEM_SSO_ISSUER cybersentineldlp-siem
    ensure_env_key GUARDRAIL_SIEM_SSO_AUDIENCE guardrail-pam \
        "The aud this GuardRail accepts. Per-consumer: do not share it with another product the SIEM signs tokens for."
    ensure_env_key GUARDRAIL_SIEM_SSO_SECRET "" \
        "Leave blank. Enables HS256, under which this server holds a key that can FORGE the SIEM's assertions rather than only verify them."
    ensure_env_key GUARDRAIL_SIEM_SSO_JIT_PROVISION true
    ensure_env_key GUARDRAIL_SIEM_SSO_SYNC_ON_LOGIN true
    ensure_env_key GUARDRAIL_SIEM_SSO_DEFAULT_ROLE Read-only
    ensure_env_key GUARDRAIL_SIEM_SSO_MAX_ROLE "" \
        "Ceiling on any SIEM-derived role. The Super Admin role is unreachable through SSO regardless of this."
    ensure_env_key GUARDRAIL_SIEM_SSO_ROLE_MAP ""
    ensure_env_key GUARDRAIL_SIEM_SSO_TRUST_AMR false
    ensure_env_key GUARDRAIL_SIEM_SSO_ALLOWLIST_BYPASS false
}

write_env() {
    local ip; ip=$(host_ip)
    umask 077
    resolve_data_paths
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
POSTGRES_PORT=${PG_PORT}
REDIS_BIND_ADDR=127.0.0.1
REDIS_PORT=${RD_PORT}
GUACD_BIND_ADDR=127.0.0.1
GUACD_PORT=${GUACD_PORT}

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

# ---- Where the data lives ----
# Blank = Docker-managed named volumes (${PROJECT}_pgdata and friends, under
# /var/lib/docker/volumes). An absolute path = that path, bind-mounted there.
#
# Do NOT repoint these by hand on a running deployment: a path with nothing in it
# starts an empty database beside the real one, and the console comes up looking
# like every tenant was deleted. Use scripts/migrate-data.sh, which moves the
# bytes and rewrites these three keys together.
GUARDRAIL_PGDATA_MOUNT=${PGDATA_MOUNT}
GUARDRAIL_RECORDINGS_MOUNT=${RECORDINGS_MOUNT}
GUARDRAIL_REDIS_MOUNT=${REDIS_MOUNT}

# ---- Session recording ----
GUARDRAIL_BROWSER_ISOLATION=true
GUARDRAIL_CHROME_PATH=
# The path the API writes to INSIDE its container. It is not where the files land
# on this host — GUARDRAIL_RECORDINGS_MOUNT above decides that — and changing it
# without changing the compose mount to match loses recordings.
GUARDRAIL_RECORDING_DIR=/var/lib/guardrail/recordings
# How long recordings are kept, in days. 0 keeps them indefinitely.
# This SEEDS an organization that has never set a policy of its own; once one is
# set in the console (Organization -> Recording retention) the stored policy is
# what is in force and this line no longer changes it. The console shows both
# values side by side.
GUARDRAIL_RECORDING_RETENTION_DAYS=90

# ---- Desktop access (RDP / VNC) ----
GUARDRAIL_DESKTOP_ENABLED=${DESKTOP_ENABLED}
GUARDRAIL_GUACD_RECORDING_DIR=${GUACD_DIR}

# ---- SIEM single sign-on ----
# Off until the two keys below are filled in. The SIEM authenticates the analyst
# and hands GuardRail a short-lived signed assertion; GuardRail never sees a
# password and never calls the SIEM back. See docs/SIEM_SSO.md.
#
# GUARDRAIL_FEDERATION_ORG_ID is the organization SSO users land in — the same
# setting OIDC and LDAP use, because it answers the same question. Without it SSO
# stays off no matter what else is set: the tenant must come from configuration
# and never from anything the token says.
GUARDRAIL_FEDERATION_ORG_ID=
# Where the SIEM publishes its public keys. HTTPS only. Setting this and the
# organization above is what turns the feature on.
GUARDRAIL_SIEM_JWKS_URL=
# The SIEM's own TLS certificate, so the fetch above is pinned to it rather than
# to whoever happens to answer. Drop the PEM in ${INSTALL_DIR}/deploy/siem/ and
# name it here by its path INSIDE the container. Needed for any SIEM with a
# self-signed certificate, which on a private network is nearly all of them.
GUARDRAIL_SIEM_JWKS_CA_BUNDLE=
# Exact strings the token must carry. The audience is per-consumer: do not reuse
# the value another product the SIEM signs for is using, or the check that the
# token was meant for GuardRail stops meaning anything.
GUARDRAIL_SIEM_SSO_ISSUER=cybersentineldlp-siem
GUARDRAIL_SIEM_SSO_AUDIENCE=guardrail-pam
# Leave this blank. It enables HS256, under which this server holds a key that
# can FORGE the SIEM's assertions rather than only verify them — and with
# just-in-time provisioning on, a leak of it mints accounts rather than merely
# impersonating one. It exists only so a SIEM that cannot yet sign with a key
# from its JWKS is not blocked. Clear it the day they can.
GUARDRAIL_SIEM_SSO_SECRET=
# Create the GuardRail account on first sign-in, and keep its role tracking the
# SIEM afterwards. Turning sync off freezes roles at whatever they were.
GUARDRAIL_SIEM_SSO_JIT_PROVISION=true
GUARDRAIL_SIEM_SSO_SYNC_ON_LOGIN=true
# The role a sign-in gets when the SIEM sends no role GuardRail recognises, and
# the ceiling on what any SIEM-derived role may become. The Super Admin role is
# unreachable through SSO whatever these say — it is what switches tenant
# isolation off, and no claim in a token gets to select it.
GUARDRAIL_SIEM_SSO_DEFAULT_ROLE=Read-only
GUARDRAIL_SIEM_SSO_MAX_ROLE=
# Optional JSON override of the role table, e.g.
#   {"L3": {"rw": "Senior Operator", "ro": "Auditor"}, "L1": "Read-only"}
GUARDRAIL_SIEM_SSO_ROLE_MAP=
# Both deliberately off. TRUST_AMR would let the SIEM's word stand in for a
# second factor somebody chose to enrol here; ALLOWLIST_BYPASS would exempt
# SIEM-vouched sessions from this organization's source-address policy. Each is
# a real control on a broker that stands in front of privileged devices, and
# neither should switch itself off as a side effect of enabling sign-on. Turn
# ALLOWLIST_BYPASS on only if analysts sign in from outside the allowed ranges.
GUARDRAIL_SIEM_SSO_TRUST_AMR=false
GUARDRAIL_SIEM_SSO_ALLOWLIST_BYPASS=false

# ---- Logging ----
GUARDRAIL_LOG_LEVEL=info
GUARDRAIL_LOG_FORMAT=json
EOF
    chmod 600 "$ENV_FILE"
    ok "configuration written to ${B}${ENV_FILE}${R} ${D}(mode 600)${R}"
    [ -n "$ip" ] && info "server address detected as ${B}${ip}${R}"
}

# ---------------------------------------------------------------------------
# Where the data lives
#
# GuardRail keeps four things that outlive a container: the database, the
# recordings, the Redis cache and the guacd handover directory. By default the
# first three are Docker-managed named volumes under /var/lib/docker/volumes,
# which is fine until the operator wants them on a data disk — at which point
# there is nowhere in the installer to say so, and moving them afterwards means
# hand-editing a compose file that the next update overwrites.
#
# So the answer is a single directory, asked once, expressed entirely through
# .env. Compose reads a mount source beginning with "/" as a bind mount and
# anything else as a named volume, so blank means the volumes and a path means
# that path — nothing in docker-compose.yml has to change either way.
#
# The prompt is offered on a FRESH INSTALL ONLY. Repointing an existing
# deployment at an empty directory starts a blank database beside a perfectly
# good one, which presents as total data loss; scripts/migrate-data.sh exists to
# move the bytes and rewrite these keys in one step.
# ---------------------------------------------------------------------------
DATA_DIR="${GUARDRAIL_DATA_DIR:-}"
PGDATA_MOUNT=""
RECORDINGS_MOUNT=""
REDIS_MOUNT=""
GUACD_DIR="/var/lib/guardrail/desktop-recordings"

ask_data_dir() {
    step "Data location"
    info "The database, the session recordings and the cache."
    info "Blank keeps them in Docker's own volumes ${D}(/var/lib/docker/volumes)${R}."
    info "A path keeps them where you say — a data disk, a mount point, anywhere you back up."
    while true; do
        ask_optional DATA_DIR "Data directory ${D}[blank = Docker volumes]${R}"
        DATA_DIR="${DATA_DIR%/}"
        if [ -z "$DATA_DIR" ]; then
            info "using Docker-managed volumes"
            return 0
        fi
        case "$DATA_DIR" in
            /) warn "not the filesystem root"; continue ;;
            /*) ;;
            *) warn "give an absolute path, starting with /"; continue ;;
        esac
        case "$DATA_DIR" in
            /var/lib/docker | /var/lib/docker/*)
                warn "that is inside Docker's own storage — leave the answer blank for that"
                continue ;;
            "$INSTALL_DIR" | "$INSTALL_DIR"/*)
                warn "that is inside ${INSTALL_DIR}, which Remove deletes wholesale"
                continue ;;
        esac
        if [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
            warn "${DATA_DIR} exists and is not a directory"
            continue
        fi
        # A directory that already holds a database is either a restore, which is
        # welcome, or another deployment, which is not. The operator has to say
        # which, because a fresh install mints a new master key and the
        # credentials already in there are encrypted under the old one.
        if [ -d "$DATA_DIR/postgres" ] && [ -n "$(ls -A "$DATA_DIR/postgres" 2>/dev/null)" ]; then
            warn "${DATA_DIR}/postgres already holds a database"
            warn "a fresh install mints a NEW vault master key, which cannot decrypt what is"
            warn "already in there — every stored device credential would become unreadable"
            local reuse=""
            ask_yn reuse "Use it anyway?" n
            [ "$reuse" = "yes" ] || continue
        fi
        info "data will live under ${B}${DATA_DIR}${R}"
        return 0
    done
}

# resolve_data_paths derives the four mount values from DATA_DIR. Blank DATA_DIR
# leaves the three mounts blank, which is what makes the compose defaults apply.
resolve_data_paths() {
    if [ -n "${DATA_DIR:-}" ]; then
        PGDATA_MOUNT="$DATA_DIR/postgres"
        RECORDINGS_MOUNT="$DATA_DIR/recordings"
        REDIS_MOUNT="$DATA_DIR/redis"
        GUACD_DIR="$DATA_DIR/desktop-recordings"
    else
        PGDATA_MOUNT=""; RECORDINGS_MOUNT=""; REDIS_MOUNT=""
        GUACD_DIR="/var/lib/guardrail/desktop-recordings"
    fi
}

# load_data_paths reads them back off an existing .env, so an update — or a
# removal — acts on wherever the data actually is rather than where a fresh
# install would have put it. Used by do_update and do_remove.
load_data_paths() {
    [ -f "$ENV_FILE" ] || { resolve_data_paths; return 0; }
    PGDATA_MOUNT=$(grep -E '^GUARDRAIL_PGDATA_MOUNT=' "$ENV_FILE" | cut -d= -f2- || true)
    RECORDINGS_MOUNT=$(grep -E '^GUARDRAIL_RECORDINGS_MOUNT=' "$ENV_FILE" | cut -d= -f2- || true)
    REDIS_MOUNT=$(grep -E '^GUARDRAIL_REDIS_MOUNT=' "$ENV_FILE" | cut -d= -f2- || true)
    GUACD_DIR=$(grep -E '^GUARDRAIL_GUACD_RECORDING_DIR=' "$ENV_FILE" | cut -d= -f2- || true)
    GUACD_DIR="${GUACD_DIR:-/var/lib/guardrail/desktop-recordings}"
}

# prepare_dirs creates whatever the configured layout needs, with the ownership
# each service requires.
#
# guacd writes desktop recordings as uid 1000 and the API reads them back through
# a shared group. Docker would otherwise create that path root:root 755, which
# guacd cannot write to — and it does not fail loudly when that happens: the
# session records nothing and says so only in a log line.
#
# The recordings directory has the same hazard for a different reason. Postgres
# and Redis chown their own data directory from their entrypoints, so an empty
# root-owned one is all they need; the API does not, because it runs as uid 65532
# and cannot chown a bind mount it was handed. A root-owned recordings directory
# means every recording fails to write while the session itself succeeds.
prepare_dirs() {
    if [ -n "$PGDATA_MOUNT" ]; then
        mkdir -p "$PGDATA_MOUNT"
        chmod 700 "$PGDATA_MOUNT" 2>/dev/null || true
    fi
    if [ -n "$REDIS_MOUNT" ]; then
        mkdir -p "$REDIS_MOUNT"
    fi
    if [ -n "$RECORDINGS_MOUNT" ]; then
        mkdir -p "$RECORDINGS_MOUNT"
        chown 65532:65532 "$RECORDINGS_MOUNT" 2>/dev/null || true
        chmod 750 "$RECORDINGS_MOUNT" 2>/dev/null || true
    fi
    mkdir -p "$GUACD_DIR"
    chown 1000:1000 "$GUACD_DIR" 2>/dev/null || true
    chmod 2770 "$GUACD_DIR" 2>/dev/null || true
}

profiles() {
    local p=()
    # `if`, not `[ ] && ...`: under set -e a failing test as the whole statement
    # is a failing command, and inside the process substitution below that exits
    # the subshell silently.
    if [ "${DNS_ENABLED:-no}" = "yes" ]; then p+=(--profile dns); fi
    if [ "${DESKTOP_ENABLED:-true}" = "true" ]; then p+=(--profile desktop); fi
    # Print nothing when there are none. `printf '%s\n' "${p[@]}"` on an EMPTY
    # array still prints one blank line, which mapfile turns into a single
    # empty-string element — and that reaches docker as an argument, giving
    # `unknown docker command: "compose "`. An install with neither the DNS
    # resolver nor desktop enabled hit this every time.
    if [ ${#p[@]} -gt 0 ]; then printf '%s\n' "${p[@]}"; fi
    return 0
}

start_stack() {
    local -a prof=()
    mapfile -t prof < <(profiles)
    step "Starting ${APP_NAME}"
    spin "pulling images (${VERSION})" \
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "${prof[@]}" pull --quiet \
        || warn "could not pull ${B}:${VERSION}${R} — starting with whatever is already on this host. If the stack does not come up, that tag has not been published yet; pick another with GUARDRAIL_VERSION=."
    # Brings up the one-shot migrate and seed containers too: `api` declares them
    # as service_completed_successfully dependencies, and compose re-runs a
    # completed one-shot on every `up`. That is what applies a release's new
    # migrations — an update does not need a separate step, and must not skip it.
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

# ---------------------------------------------------------------------------
# Bootstrap API token
# ---------------------------------------------------------------------------
#
# A fresh install ends with a working machine credential in hand, so a monitoring
# box can start polling without anyone first having to log in, find the console,
# and mint one by hand.
#
# Read-only, and narrower than the full set the console offers: the estate scopes
# a status board actually needs, without user:read / role:read / org:read. "What
# is on the network" and "who works here" are different questions, and an
# unattended credential in a config file should only be able to answer the first.
BOOTSTRAP_TOKEN=""
BOOTSTRAP_TOKEN_NAME="installer-bootstrap"
BOOTSTRAP_TOKEN_SCOPES='["device:read","session:read","recording:read","group:read","log:read","report:read"]'

# Minimal JSON string escaping, for values we interpolate into a request body.
# An admin password is free text: one embedded quote or backslash would otherwise
# produce a malformed body and a login failure nobody could explain.
json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

# json_str KEY CHARCLASS — pull one string value out of a JSON response.
#
# Narrow by design rather than a general parser: the class is the exact alphabet
# the wanted value can contain, so a match cannot run off the end of the field
# into a neighbouring one. Avoids a hard dependency on jq, which is not installed
# on the bare servers this script targets.
json_str() {
    grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"$2+\"" | head -n1 | sed -E 's/.*:[[:space:]]*"(.*)"$/\1/'
}

mint_api_token() {
    BOOTSTRAP_TOKEN=""
    local base="https://127.0.0.1:${HTTPS_PORT}/api/v1"
    local login jwt created tries=3

    local body
    body=$(printf '{"email":"%s","password":"%s"}' \
        "$(json_escape "$ADMIN_EMAIL")" "$(json_escape "$ADMIN_PASSWORD")")

    # healthz answering means the process is up; the bootstrap admin is created
    # during start-up and is normally there already, but a slow first migration
    # can land it a second or two later. Retry rather than race it.
    while [ "$tries" -gt 0 ]; do
        login=$(curl -sk --max-time 15 -X POST "$base/auth/login" \
            -H 'Content-Type: application/json' -d "$body" 2>/dev/null) || true
        jwt=$(printf '%s' "$login" | json_str access_token '[A-Za-z0-9._-]')
        [ -n "$jwt" ] && break
        tries=$((tries - 1))
        [ "$tries" -gt 0 ] && sleep 2
    done

    if [ -z "$jwt" ]; then
        warn "could not sign in as ${ADMIN_EMAIL} to mint an API token"
        info "mint one from the console instead: Account → API tokens"
        return 0
    fi

    created=$(curl -sk --max-time 15 -X POST "$base/api-tokens" \
        -H "Authorization: Bearer ${jwt}" -H 'Content-Type: application/json' \
        -d "{\"name\":\"${BOOTSTRAP_TOKEN_NAME}\",\"scopes\":${BOOTSTRAP_TOKEN_SCOPES}}" 2>/dev/null) || true
    BOOTSTRAP_TOKEN=$(printf '%s' "$created" | json_str token 'grt_[A-Za-z0-9_-]')

    if [ -z "$BOOTSTRAP_TOKEN" ]; then
        warn "signed in, but could not mint an API token"
        info "mint one from the console instead: Account → API tokens"
    fi
    return 0
}

summary() {
    local ip; ip=$(host_ip)
    local url="https://${ip:-127.0.0.1}${HTTPS_PORT:+:$HTTPS_PORT}"
    step "${APP_NAME} is running"
    printf '\n'
    printf '    %s  %s\n' "${B}Console${R}" "$url"
    printf '    %s    %s\n' "${B}Admin${R}" "${ADMIN_EMAIL:-$(grep -E '^GUARDRAIL_ADMIN_EMAIL=' "$ENV_FILE" | cut -d= -f2-)}"
    printf '    %s   %s\n' "${B}Config${R}" "$ENV_FILE"
    if [ -n "${PGDATA_MOUNT:-}" ]; then
        printf '    %s     %s\n' "${B}Data${R}" "$(dirname "$PGDATA_MOUNT")"
    else
        printf '    %s     %s\n' "${B}Data${R}" "Docker volumes ${D}(/var/lib/docker/volumes/${PROJECT}_*)${R}"
    fi
    if [ "${DNS_ENABLED:-no}" = "yes" ]; then
        printf '    %s      %s\n' "${B}DNS${R}" "point clients at ${ip} for *.${TUNNEL_DOMAIN}"
    fi

    if [ -n "$BOOTSTRAP_TOKEN" ]; then
        printf '\n'
        printf '  %s\n' "${B}API token${R} ${D}(${BOOTSTRAP_TOKEN_NAME} · read-only)${R}"
        printf '\n'
        printf '    %s\n' "${GRN}${B}${BOOTSTRAP_TOKEN}${R}"
        printf '\n'
        # Said here because it is true and because the alternative — someone
        # assuming they can scroll back for it next week — ends in a support
        # question with no answer.
        printf '  %s\n' "${YLW}Copy it now. Only its hash is stored; this is the only time it is shown.${R}"
        printf '  %s\n' "${D}It does not expire. Revoke or replace it in the console: Account → API tokens.${R}"
        printf '\n'
        printf '  %s\n' "${D}Try it:${R}"
        printf '    %s\n' "${D}curl -sk ${url}/api/v1/status/devices \\${R}"
        printf '    %s\n' "${D}     -H \"Authorization: Bearer ${BOOTSTRAP_TOKEN}\"${R}"
    fi

    printf '\n'
    printf '  %s\n' "${D}The certificate is self-signed: your browser will warn once.${R}"
    printf '  %s\n' "${D}Change the admin password after first sign-in (Account → Password).${R}"
    printf '  %s\n' "${D}Manage: sudo $0${R}"
    printf '  %s\n\n' "${D}Move the data to another disk: sudo ${INSTALL_DIR}/migrate-data.sh${R}"
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

    # Existing data + no config we wrote = a deployment that was set up some other
    # way (a git checkout, an older installer, a restored backup). Installing over
    # it would generate a NEW GUARDRAIL_MASTER_KEY and hand it a database whose
    # credentials are encrypted under the OLD one — every vaulted device password
    # becomes permanently unreadable, and nothing announces it until someone tries
    # to connect. The Postgres password would not match the initialised volume
    # either, so the stack would not even start.
    #
    # This is the one case where the installer stops rather than asks nicely.
    local existing
    [ "${DETECTED}" = "1" ] || true   # detection already reported what is here
    existing=$(data_volumes)
    if [ -n "$existing" ] && [ ! -f "$ENV_FILE" ]; then
        step "Refusing to install over existing data"
        err "these volumes already hold a GuardRail deployment under project '${PROJECT}':"
        printf '%s\n' "$existing" | sed 's/^/      /' >&2
        echo >&2
        err "a fresh install mints a new vault master key, which CANNOT decrypt the"
        err "credentials already in that database. Installing here would destroy them."
        echo >&2
        info "to upgrade that deployment instead, choose ${B}Update${R}"
        info "to try this build alongside it, run a separate instance:"
        printf '\n      %s\n\n' "GUARDRAIL_PROJECT=guardrail-test GUARDRAIL_DIR=/opt/guardrail-test \\"
        printf '      %s\n\n' "  sudo -E bash $0     # then pick ports other than 443/80"
        return 1
    fi

    step "Configuration"
    ask_port HTTPS_PORT "HTTPS port (console, API and sessions)" 443
    ask_port HTTP_PORT  "HTTP port (redirects to HTTPS)" 80
    ask ADMIN_EMAIL "Admin email" "admin@example.com"
    ask_password ADMIN_PASSWORD
    ask_yn DESKTOP_YN "Enable desktop access (RDP/VNC via guacd)?" y
    DESKTOP_ENABLED=$([ "$DESKTOP_YN" = "yes" ] && echo true || echo false)

    ask_data_dir
    resolve_data_paths

    configure_dns "tunnel.guardrail.lan" "yes"

    # Loopback-published for psql/backups; shifted if something already holds them.
    PG_PORT=$(free_port 5432);  note_port Postgres 5432 "$PG_PORT"
    RD_PORT=$(free_port 6379);  note_port Redis 6379 "$RD_PORT"
    GUACD_PORT=$(free_port 4822); note_port guacd 4822 "$GUACD_PORT"

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
    mint_api_token
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

    # Where the data lives is read back off the .env rather than re-derived, so an
    # update leaves it exactly where the operator put it — including a layout
    # migrate-data.sh moved to a disk this installer has never heard of.
    load_data_paths

    # Rewrite only the keys this update owns. The secrets, the admin credential
    # and the database passwords are left untouched: regenerating the master key
    # would orphan every credential in the vault.
    sed -i \
        -e "s|^VERSION=.*|VERSION=${VERSION}|" \
        -e "s|^GUARDRAIL_TUNNEL_DOMAIN=.*|GUARDRAIL_TUNNEL_DOMAIN=${TUNNEL_DOMAIN}|" \
        -e "s|^GUARDRAIL_DNS_UPSTREAM=.*|GUARDRAIL_DNS_UPSTREAM=${DNS_UPSTREAM}|" \
        "$ENV_FILE"
    grep -q '^GUARDRAIL_DNS_UPSTREAM=' "$ENV_FILE" || echo "GUARDRAIL_DNS_UPSTREAM=${DNS_UPSTREAM}" >>"$ENV_FILE"
    migrate_env
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
    # Read before anything is deleted: the .env that says where the data lives is
    # itself inside the directory this removes.
    load_data_paths

    step "Remove ${APP_NAME} completely"
    warn "this deletes the containers, the images, the DATABASE, the credential"
    warn "vault and every session recording. It cannot be undone."

    # Named the operator can see, because bind-mounted data is deleted by path
    # here rather than by `down -v`, and a path is worth reading twice.
    local -a bind_data=()
    if [ -n "$PGDATA_MOUNT" ];     then bind_data+=("$PGDATA_MOUNT"); fi
    if [ -n "$RECORDINGS_MOUNT" ]; then bind_data+=("$RECORDINGS_MOUNT"); fi
    if [ -n "$REDIS_MOUNT" ];      then bind_data+=("$REDIS_MOUNT"); fi
    if [ ${#bind_data[@]} -gt 0 ]; then
        echo
        warn "these directories hold the data and will be deleted:"
        local d
        for d in "${bind_data[@]}"; do printf '      %s\n' "${B}${d}${R}" >&2; done
    fi

    # Anything else on this host under a different project name. Remove is scoped
    # to THIS instance, and the shared bits below are only safe to delete when
    # nothing else is using them.
    local others=""
    if have docker; then
        others=$(docker ps -a --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null |
            grep -E '^guardrail' | grep -vx "$PROJECT" | sort -u || true)
    fi
    if [ -n "$others" ]; then
        echo
        info "other GuardRail instances on this host will be left alone:"
        printf '%s\n' "$others" | sed 's/^/      /'
    fi
    echo
    local confirm=""
    read_input confirm "  Type ${B}REMOVE${R} to confirm: " || no_input
    [ "$confirm" = "REMOVE" ] || { info "cancelled — nothing was removed"; return 0; }

    if [ -f "$COMPOSE_FILE" ]; then
        # -v takes the named volumes with it; without it the database survives and
        # a later install silently adopts an old vault it has no key for. Volumes
        # are project-scoped, so this only ever touches this instance's data.
        spin "removing containers and volumes" bash -c \
            "docker compose -p '$PROJECT' --env-file '$ENV_FILE' -f '$COMPOSE_FILE' --profile dns --profile desktop down -v --remove-orphans" \
            || true
    fi
    # Sweep anything left over from an interrupted run, by project label.
    if have docker; then
        local leftovers
        leftovers=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)
        if [ -n "$leftovers" ]; then
            # shellcheck disable=SC2086 # deliberately word-split: a list of ids
            docker rm -f $leftovers >/dev/null 2>&1 || true
        fi
        # Images are NOT removed.
        #
        # They are shared: `docker images | grep guardrail | xargs docker rmi -f`
        # deletes the images every other instance on the host is running from, and
        # a `grep guardrail` matches anything with that substring. Removing this
        # instance must not leave another one unable to restart. Docker prunes
        # unreferenced images on request; that is the operator's call, not ours.
        info "images left in place — other instances may share them"
        info "to reclaim that space: ${D}docker image prune -a${R}"
    fi

    rm -rf "$INSTALL_DIR"

    # Bind-mounted data is invisible to `down -v`. That removes named volumes,
    # and a path is not one — so a deployment whose data was relocated would keep
    # its database and every recording on disk while Remove reported success.
    #
    # /var/lib/guardrail is a HOST path shared by every instance (guacd writes
    # desktop recordings there), not a project-scoped volume. Deleting it while
    # another instance is running removes the directory out from under its guacd,
    # which then records nothing and says so only in a log line. A data directory
    # the operator named is theirs alone in the normal case, but the same guard
    # applies to it: sharing one between two instances is their prerogative, and
    # the cost of guessing wrong is somebody else's database.
    # The three data mounts are named in THIS project's .env and were created for
    # it, so they go unconditionally. Only the shared default path below is
    # subject to the other-instances guard — an earlier version applied that guard
    # to everything, which meant Remove promised to delete the database and then
    # quietly left it on disk whenever any other GuardRail existed on the host.
    local d
    for d in "${bind_data[@]}"; do
        rm -rf -- "$d"
        info "removed ${d}"
    done

    if [ "$GUACD_DIR" = "/var/lib/guardrail/desktop-recordings" ] && [ -n "$others" ]; then
        info "left ${GUACD_DIR} alone — it is the shared default path and another"
        info "instance on this host bind-mounts it"
    else
        rm -rf -- "$GUACD_DIR"
        # Only ours in the default layout; rmdir declines if it holds anything else.
        rmdir "$(dirname "$GUACD_DIR")" 2>/dev/null || true
        info "removed ${GUACD_DIR}"
    fi
    ok "removed: containers, volumes, ${INSTALL_DIR} and the data directories"
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
