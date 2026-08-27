#!/usr/bin/env bash
#
# GuardRail — wire up SIEM single sign-on, in one command.
#
#   sudo /opt/guardrail/siem-sso.sh https://10.200.10.23:3000/api/sso/jwks.json
#   sudo /opt/guardrail/siem-sso.sh status
#   sudo /opt/guardrail/siem-sso.sh off
#
# It fetches the SIEM's TLS certificate, shows you what it is before trusting it,
# pins it, writes the .env keys, restarts the API and checks that the result
# actually works. Everything it does by hand is in docs/SIEM_SSO.md; this exists
# because the manual path is four steps, one of which is an openssl incantation
# nobody remembers and one of which is the `up -d` vs `restart` trap.
#
# Design notes worth knowing before editing:
#
#   * The certificate is SHOWN and CONFIRMED before it is installed. The whole
#     value of pinning is that a person decided which certificate is the right
#     one; fetching and trusting in one silent step is trust-on-first-use with
#     extra typing, and TOFU against whoever happens to answer that address is
#     most of what pinning was meant to prevent.
#   * It verifies the JWKS actually fetches THROUGH the pinned certificate before
#     writing anything to .env. A configuration that is written and then found to
#     be broken is worse than one that was never written: the operator walks away
#     believing it is done.
#   * .env is rewritten in place (">", not "mv") so its mode 0600 and its inode
#     survive. It is the only copy of the master key.
set -euo pipefail

INSTALL_DIR="${GUARDRAIL_DIR:-/opt/guardrail}"
PROJECT="${GUARDRAIL_PROJECT:-guardrail}"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
CERT_DIR="$INSTALL_DIR/deploy/siem"
CERT_HOST_PATH="$CERT_DIR/jwks-ca.pem"
# The path INSIDE the api container, where deploy/siem is bind-mounted read-only.
CERT_CONTAINER_PATH="/etc/guardrail/siem/jwks-ca.pem"

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

# Prompts read from the terminal on fd 3, not stdin, so this still works when the
# script is piped. Each helper carries its OWN variable prefix: `local` is visible
# to called functions in bash, so a callee whose internals share a name with the
# caller's output variable silently writes to its own copy and every prompt
# returns its default. That bug is invisible until every answer is wrong.
exec 3<&0 || true
ask_yn() { # ask_yn VAR "Prompt" "y|n"
    local __yn_var="$1" __yn_prompt="$2" __yn_default="${3:-y}" __yn_ans=""
    local __yn_hint="[Y/n]"; [ "$__yn_default" = "n" ] && __yn_hint="[y/N]"
    while true; do
        printf '%s' "  ${__yn_prompt} ${D}${__yn_hint}${R}: "
        IFS= read -r -u 3 __yn_ans || die "no input available — run this from a terminal"
        __yn_ans="${__yn_ans:-$__yn_default}"
        case "${__yn_ans,,}" in
            y|yes) printf -v "$__yn_var" '%s' yes; return 0 ;;
            n|no)  printf -v "$__yn_var" '%s' no;  return 0 ;;
            *) warn "answer y or n" ;;
        esac
    done
}

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

# env_set KEY VALUE — rewrites .env in place, preserving mode and inode.
env_set() {
    local key=$1 val=$2 tmp
    tmp=$(mktemp)
    if grep -qE "^${key}=" "$ENV_FILE"; then
        # awk, not sed: a URL and a filesystem path are free text, and every sed
        # delimiter worth using is a character one of them is allowed to contain.
        awk -v k="$key" -v v="$val" -F= '$1==k {print k "=" v; next} {print}' "$ENV_FILE" >"$tmp"
    else
        cat "$ENV_FILE" >"$tmp"
        printf '%s=%s\n' "$key" "$val" >>"$tmp"
    fi
    cat "$tmp" >"$ENV_FILE"
    rm -f "$tmp"
}

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true; }

# env_or KEY FALLBACK — what env_get says, or FALLBACK when the key is absent OR
# present-but-blank. A blank value is the normal state for most of these keys, so
# defaulting on exit status alone would print an empty column where a sentence
# belongs.
env_or() { local v; v=$(env_get "$1"); printf '%s' "${v:-$2}"; }

require_install() {
    [ -f "$COMPOSE_FILE" ] || die "no GuardRail deployment at ${INSTALL_DIR} — run install.sh first"
    [ -f "$ENV_FILE" ] || die "no ${ENV_FILE} — run install.sh first"
    [ "$(id -u)" = "0" ] || die "run this with sudo — it writes ${ENV_FILE} and restarts the stack"
}

usage() {
    cat <<USAGE
${B}GuardRail — SIEM single sign-on${R}

  ${B}sudo $0${R} ${CYN}<jwks-url>${R} [options]     set it up
  ${B}sudo $0 status${R}                    show what is configured now
  ${B}sudo $0 off${R}                       turn it off (keeps the certificate)

Options
  --secret ${D}<hex>${R}     also accept HS256 tokens signed with this shared secret.
                    A migration aid only: it hands this server a key that can
                    FORGE the SIEM's assertions rather than merely check them.
                    Clear it the day the SIEM signs from its JWKS.
  --org ${D}<slug>${R}       which organization SIEM users land in. Defaults to the
                    only one on this deployment, which is almost always right.
  --audience ${D}<s>${R}     the aud this GuardRail accepts   ${D}(default: guardrail-pam)${R}
  --issuer ${D}<s>${R}       the iss tokens must carry        ${D}(default: cybersentineldlp-siem)${R}
  --max-role ${D}<s>${R}     ceiling on any SSO-derived role, e.g. "Operator"
  --no-verify       skip the post-restart check (not recommended)

Example
  sudo $0 https://10.200.10.23:3000/api/sso/jwks.json
USAGE
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
show_status() {
    require_install
    step "SIEM single sign-on"
    local url; url=$(env_get GUARDRAIL_SIEM_JWKS_URL)
    local secret; secret=$(env_get GUARDRAIL_SIEM_SSO_SECRET)
    if [ -z "$url" ] && [ -z "$secret" ]; then
        info "not configured"
        info "set it up with: ${B}sudo $0 <jwks-url>${R}"
        return 0
    fi
    printf '  %-22s %s\n' "JWKS URL" "${url:-(none)}"
    printf '  %-22s %s\n' "pinned certificate" "$(env_or GUARDRAIL_SIEM_JWKS_CA_BUNDLE '(system trust store — not pinned)')"
    printf '  %-22s %s\n' "issuer" "$(env_get GUARDRAIL_SIEM_SSO_ISSUER)"
    printf '  %-22s %s\n' "audience" "$(env_get GUARDRAIL_SIEM_SSO_AUDIENCE)"
    printf '  %-22s %s\n' "organization" "$(env_or GUARDRAIL_SIEM_SSO_ORG '(the only one on this deployment)')"
    printf '  %-22s %s\n' "default role" "$(env_get GUARDRAIL_SIEM_SSO_DEFAULT_ROLE)"
    printf '  %-22s %s\n' "role ceiling" "$(env_or GUARDRAIL_SIEM_SSO_MAX_ROLE '(none — Super Admin is barred regardless)')"
    if [ -n "$secret" ]; then
        warn "a shared secret is set: this server holds a key that can FORGE the SIEM's"
        warn "assertions. Clear GUARDRAIL_SIEM_SSO_SECRET once the SIEM signs from its JWKS."
    fi
    if [ -f "$CERT_HOST_PATH" ]; then
        local expiry; expiry=$(openssl x509 -in "$CERT_HOST_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
        # Worth surfacing every time: when this expires, SSO stops working and
        # nothing else does, so the symptom looks like a GuardRail fault.
        info "pinned certificate expires ${B}${expiry}${R}"
    fi
    probe_live
}

# console_url is where this deployment actually listens.
#
# Read from .env rather than assumed to be 443: install.sh lets the operator
# choose the port, and shifts it when something else already holds it. Hard-coding
# 443 makes a perfectly good setup on port 8443 report "could not confirm" — an
# alarming message about a working configuration, which is the kind of thing
# people spend an afternoon chasing.
console_url() {
    local port; port=$(env_or GUARDRAIL_HTTPS_PORT 443)
    printf 'https://127.0.0.1:%s' "$port"
}

probe_live() {
    local out
    out=$(curl -sk --max-time 5 "$(console_url)/api/v1/auth/providers" 2>/dev/null || true)
    case "$out" in
        *'"siem_sso":true'*)  ok "the running API reports SIEM single sign-on as ${B}enabled${R}" ;;
        *'"siem_sso":false'*) warn "the running API reports it as DISABLED — it may not have been restarted"
                              info "run: ${B}cd ${INSTALL_DIR} && docker compose up -d api${R}" ;;
        *) info "could not reach the API on this host to confirm ${D}(that is fine if it is bound elsewhere)${R}" ;;
    esac
}

# ---------------------------------------------------------------------------
# off
# ---------------------------------------------------------------------------
turn_off() {
    require_install
    step "Turning SIEM single sign-on off"
    env_set GUARDRAIL_SIEM_JWKS_URL ""
    env_set GUARDRAIL_SIEM_SSO_SECRET ""
    ok "key material cleared — the certificate is left in ${D}${CERT_HOST_PATH}${R}"
    info "applying"
    compose up -d api >/dev/null 2>&1 || die "could not restart the api service"
    ok "done"
}

# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
JWKS_URL=""; SECRET=""; ORG=""; AUDIENCE=""; ISSUER=""; MAX_ROLE=""; VERIFY=1

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --secret)    SECRET="${2:-}"; shift 2 ;;
            --org)       ORG="${2:-}"; shift 2 ;;
            --audience)  AUDIENCE="${2:-}"; shift 2 ;;
            --issuer)    ISSUER="${2:-}"; shift 2 ;;
            --max-role)  MAX_ROLE="${2:-}"; shift 2 ;;
            --no-verify) VERIFY=0; shift ;;
            -h|--help)   usage; exit 0 ;;
            -*)          die "unknown option $1" ;;
            *)           JWKS_URL="$1"; shift ;;
        esac
    done
}

# host_port_of extracts host:port from a URL, defaulting to 443.
host_port_of() {
    local u=${1#*://} hostport=${1#*://}
    hostport=${hostport%%/*}
    case "$hostport" in
        *:*) printf '%s' "$hostport" ;;
        *)   printf '%s:443' "$hostport" ;;
    esac
    : "$u"
}

fetch_certificate() {
    local hostport=$1 tmp
    tmp=$(mktemp)
    # Bounded. A refused connection fails instantly, but a black-holed address —
    # a firewall that drops rather than rejects, which is the normal posture in
    # front of a SIEM — leaves openssl sitting on the kernel's TCP timeout for
    # over two minutes with nothing on screen. Ten seconds is long enough for any
    # host worth pinning and short enough to read as an answer.
    #
    # -showcerts prints the whole chain; the LAST certificate is the root or, for
    # a self-signed leaf, the leaf itself — which is the one to pin either way.
    if ! timeout 10 openssl s_client -connect "$hostport" -showcerts </dev/null 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' >"$tmp"; then
        rm -f "$tmp"; return 1
    fi
    [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
    # Keep the last certificate in the chain.
    awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} {block[n]=block[n] $0 "\n"} END{printf "%s", block[n]}' "$tmp" >"$tmp.last"
    mv "$tmp.last" "$tmp"
    printf '%s' "$tmp"
}

do_setup() {
    require_install
    [ -n "$JWKS_URL" ] || { usage; exit 1; }
    case "$JWKS_URL" in
        https://*) ;;
        http://*) die "the JWKS URL must be https — over plain HTTP the key set did not come from anywhere in particular, and whoever answers it chooses who may sign in" ;;
        *) die "give the full JWKS URL, e.g. https://10.200.10.23:3000/api/sso/jwks.json" ;;
    esac
    command -v openssl >/dev/null || die "openssl is required"
    command -v curl >/dev/null || die "curl is required"

    local hostport; hostport=$(host_port_of "$JWKS_URL")
    step "SIEM certificate"
    info "asking ${B}${hostport}${R} for the certificate it presents"

    local tmpcert
    if ! tmpcert=$(fetch_certificate "$hostport"); then
        die "could not reach ${hostport} — check the address, the port and that this server can route to it"
    fi

    printf '\n'
    openssl x509 -in "$tmpcert" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
    openssl x509 -in "$tmpcert" -noout -fingerprint -sha256 2>/dev/null | sed 's/^/    /'
    printf '\n'
    # Confirmed by a person, deliberately. Pinning is only worth anything if
    # somebody decided this is the right certificate; fetch-and-trust in one
    # silent step is trust-on-first-use against whoever answered that address.
    info "this is what GuardRail will trust to say who may sign in."
    info "check the fingerprint against what the SIEM's owner tells you it should be."
    local yn; ask_yn yn "Pin this certificate?" y
    [ "$yn" = "yes" ] || { rm -f "$tmpcert"; die "nothing was changed"; }

    mkdir -p "$CERT_DIR"
    cat "$tmpcert" >"$CERT_HOST_PATH"
    chmod 644 "$CERT_HOST_PATH"
    rm -f "$tmpcert"
    ok "pinned to ${D}${CERT_HOST_PATH}${R}"

    # Prove it works BEFORE writing any configuration. A setting that is written
    # and then found to be broken is worse than one never written: the operator
    # walks away believing the job is done.
    step "Checking the key set"
    local body
    if ! body=$(curl -sS --max-time 10 --cacert "$CERT_HOST_PATH" "$JWKS_URL" 2>&1); then
        err "could not fetch the key set through the pinned certificate:"
        printf '    %s\n' "$body" >&2
        warn "the certificate must also MATCH the host in the URL, so ${hostport%%:*} has to be in its SAN."
        warn "nothing was written to ${ENV_FILE}; the certificate is at ${CERT_HOST_PATH}."
        exit 1
    fi
    case "$body" in
        *'"keys"'*) ;;
        *) die "that URL answered, but not with a JWKS (no \"keys\" member). Check the path." ;;
    esac
    local n; n=$(printf '%s' "$body" | grep -o '"kty"' | wc -l | tr -d ' ')
    ok "fetched ${B}${n}${R} key(s) over a pinned connection"
    case "$body" in
        *'"kid"'*) ;;
        *) warn "no kid in the key set — ask the SIEM to name its keys, or rotation will need a flag day" ;;
    esac

    step "Configuration"
    env_set GUARDRAIL_SIEM_JWKS_URL "$JWKS_URL"
    env_set GUARDRAIL_SIEM_JWKS_CA_BUNDLE "$CERT_CONTAINER_PATH"
    [ -n "$AUDIENCE" ] && env_set GUARDRAIL_SIEM_SSO_AUDIENCE "$AUDIENCE"
    [ -n "$ISSUER" ]   && env_set GUARDRAIL_SIEM_SSO_ISSUER "$ISSUER"
    [ -n "$ORG" ]      && env_set GUARDRAIL_SIEM_SSO_ORG "$ORG"
    [ -n "$MAX_ROLE" ] && env_set GUARDRAIL_SIEM_SSO_MAX_ROLE "$MAX_ROLE"
    if [ -n "$SECRET" ]; then
        if [ "${#SECRET}" -lt 32 ]; then
            die "that shared secret is ${#SECRET} characters — too short to be worth having. Use at least 32."
        fi
        env_set GUARDRAIL_SIEM_SSO_SECRET "$SECRET"
        warn "HS256 enabled. This server now holds a key that can FORGE the SIEM's"
        warn "assertions, not merely verify them. Clear it once the SIEM signs from its JWKS:"
        warn "  ${B}sudo $0 <jwks-url>${R}   ${D}(without --secret)${R}"
    fi
    ok "written to ${D}${ENV_FILE}${R}"
    printf '  %-32s %s\n' "GUARDRAIL_SIEM_JWKS_URL" "$JWKS_URL"
    printf '  %-32s %s\n' "GUARDRAIL_SIEM_JWKS_CA_BUNDLE" "$CERT_CONTAINER_PATH"
    printf '  %-32s %s\n' "GUARDRAIL_SIEM_SSO_AUDIENCE" "$(env_get GUARDRAIL_SIEM_SSO_AUDIENCE)"
    printf '  %-32s %s\n' "GUARDRAIL_SIEM_SSO_ISSUER" "$(env_get GUARDRAIL_SIEM_SSO_ISSUER)"
    printf '  %-32s %s\n' "GUARDRAIL_SIEM_SSO_ORG" "$(env_or GUARDRAIL_SIEM_SSO_ORG '(the only organization on this deployment)')"

    step "Applying"
    # up -d, never restart: a restart reuses the container's existing environment,
    # so every value just written would be ignored and the check below would fail
    # for a reason that has nothing to do with the configuration.
    compose up -d api >/dev/null 2>&1 || die "could not recreate the api service"
    ok "api recreated with the new environment"

    if [ "$VERIFY" = "1" ]; then
        step "Verifying"
        local i=0
        while [ $i -lt 30 ]; do
            case "$(curl -sk --max-time 3 "$(console_url)/api/v1/auth/providers" 2>/dev/null || true)" in
                *'"siem_sso":true'*) ok "the API reports SIEM single sign-on as ${B}enabled${R}"; break ;;
            esac
            i=$((i + 1)); sleep 2
        done
        if [ $i -ge 30 ]; then
            warn "the API did not report SSO as enabled within a minute"
            info "check: ${B}cd ${INSTALL_DIR} && docker compose logs api | grep -i sso${R}"
        fi
    fi

    step "Now tell the SIEM"
    cat <<NEXT
  Redirect the analyst's browser to:

      ${B}https://<this-console>/auth/sso#token=<exchange-token>${R}

  The token is a JWS carrying:
      purpose  "sso_exchange"
      iss      "$(env_get GUARDRAIL_SIEM_SSO_ISSUER)"
      aud      "$(env_get GUARDRAIL_SIEM_SSO_AUDIENCE)"     ${D}← GuardRail's own; not the DLP's${R}
      sub      the SIEM's immutable user id ${D}(not the email)${R}
      nonce    fresh per token
      exp      about 30 seconds out
      email, role ${D}(Administrator|L1|L2|L3)${R}, access ${D}(read-write|read-only)${R}

  Fragment ${B}#${R}, not query ${B}?${R} — a query string writes a live credential
  into the proxy access log, browser history and the next Referer.

  Full detail: ${D}docs/SIEM_SSO.md${R}
NEXT
}

main() {
    case "${1:-}" in
        ""|-h|--help) usage; exit 0 ;;
        status)       show_status; exit 0 ;;
        off)          turn_off; exit 0 ;;
    esac
    parse_args "$@"
    do_setup
}

main "$@"
