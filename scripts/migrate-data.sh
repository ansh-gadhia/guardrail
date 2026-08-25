#!/usr/bin/env bash
#
# GuardRail data migrator — relocate a running deployment's data to another disk.
#
#   sudo ./migrate-data.sh
#
# What it moves is the four things that survive `docker compose down`:
#
#   the Postgres database        orgs, users, devices, credentials, the audit chain
#   session recordings           the blob store the audit log points at
#   the Redis cache              refresh tokens; disposable, moved for tidiness
#   the desktop recording dir    guacd -> API handover scratch
#
# It does NOT move /opt/guardrail. That directory holds configuration and the
# TLS material, not data; it is small, it is where the installer expects to find
# a deployment, and moving it would break `install.sh` for everyone who does not
# also know to set GUARDRAIL_DIR. Back it up — do not relocate it.
#
# Design notes worth knowing before editing:
#
#   * The relocation is expressed in .env, not by editing service definitions.
#     docker-compose.yml is re-fetched from the repository on every update
#     (install.sh:fetch_release), so an edit made to it here would be silently
#     reverted the next time someone updates — and a compose file that has gone
#     back to naming `pgdata` while the data lives on another disk starts an
#     EMPTY database next to a perfectly good one. .env is preserved across
#     updates, which is the only reason this is safe.
#   * Compose reads a mount source beginning with "/" as a bind mount and
#     anything else as a named volume. That one rule is the whole mechanism:
#     GUARDRAIL_PGDATA_MOUNT unset means the volume `pgdata`, set to a path means
#     that path, and nothing else in the file has to change.
#   * Nothing is deleted until the stack is back up AND the containers have been
#     inspected to confirm they are actually reading from the new location. A
#     migrator that deletes on the strength of "the copy returned 0" is one
#     mis-set variable away from destroying the only copy.
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_NAME="GuardRail"
INSTALL_DIR="${GUARDRAIL_DIR:-/opt/guardrail}"
PROJECT="${GUARDRAIL_PROJECT:-guardrail}"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

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

have() { command -v "$1" >/dev/null 2>&1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"; }

compose() { docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

# Answers come from fd 3 so that `curl ... | sudo bash` still gets a terminal.
setup_input() { exec 3</dev/tty 2>/dev/null || exec 3<&0; }
no_input() { die "no input available — run this from a terminal"; }

# These write their answer into a caller-named variable, which makes shadowing a
# real hazard: a helper whose local happens to share a name with the variable it
# was asked to fill assigns to ITS OWN copy, the caller sees nothing, and the
# prompt silently returns its default. Sharing one prefix across all of them is
# not enough — that just moves the collision. Each function declares only its own
# __<self>_ names, so a caller passing one of its own can never collide.
read_input() { # read_input VAR [prompt] — non-zero at EOF
    local __ri_v="$1" __ri_p="${2:-}" __ri_a=""
    [ -n "$__ri_p" ] && printf '%s' "$__ri_p"
    IFS= read -r -u 3 __ri_a || return 1
    printf -v "$__ri_v" '%s' "$__ri_a"
}

ask() { # ask VAR "Prompt" "default"
    local __ask_v="$1" __ask_p="$2" __ask_d="${3:-}" __ask_a=""
    if [ -n "$__ask_d" ]; then
        read_input __ask_a "  ${__ask_p} ${D}[${__ask_d}]${R}: " || no_input
        __ask_a="${__ask_a:-$__ask_d}"
    else
        while [ -z "$__ask_a" ]; do read_input __ask_a "  ${__ask_p}: " || no_input; done
    fi
    printf -v "$__ask_v" '%s' "$__ask_a"
}

ask_yn() { # ask_yn VAR "Prompt" "y|n"
    local __yn_v="$1" __yn_p="$2" __yn_d="${3:-y}" __yn_a="" __yn_h="[Y/n]"
    [ "$__yn_d" = "n" ] && __yn_h="[y/N]"
    while true; do
        read_input __yn_a "  ${__yn_p} ${D}${__yn_h}${R}: " || no_input
        __yn_a="${__yn_a:-$__yn_d}"
        case "${__yn_a,,}" in
            y|yes) printf -v "$__yn_v" '%s' yes; return 0 ;;
            n|no)  printf -v "$__yn_v" '%s' no;  return 0 ;;
            *) warn "answer y or n" ;;
        esac
    done
}

spin() {
    local msg="$1"; shift
    if [ ! -t 1 ]; then printf '  ▸ %s\n' "$msg"; "$@"; return; fi
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 rc=0 log
    log=$(mktemp)
    "$@" >"$log" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i + 1) % ${#frames} ))
        printf '\r  %s %s' "${CYN}${frames:$i:1}${R}" "$msg"
        sleep 0.08
    done
    wait "$pid" || rc=$?
    if [ "$rc" -eq 0 ]; then printf '\r  %s %s\n' "${GRN}✔${R}" "$msg"
    else printf '\r  %s %s\n' "${RED}✘${R}" "$msg"; sed 's/^/      /' "$log" >&2; fi
    rm -f "$log"
    return "$rc"
}

human() { # human BYTES
    if have numfmt; then numfmt --to=iec --suffix=B "${1:-0}"; else printf '%s bytes' "${1:-0}"; fi
}

# ---------------------------------------------------------------------------
# .env access
#
# Read and write in place, preserving mode 0600 — the file holds the vault master
# key, and a migrator that widens its permissions has done more damage than the
# disk it was called in to fix.
# ---------------------------------------------------------------------------
env_get() { # env_get KEY
    [ -f "$ENV_FILE" ] || return 0
    grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true
}

env_set() { # env_set KEY VALUE
    local key=$1 val=$2 tmp
    tmp=$(mktemp)
    if grep -qE "^${key}=" "$ENV_FILE"; then
        # awk rather than sed: a filesystem path is free text, and every sed
        # delimiter worth using is a character a path is allowed to contain.
        awk -v k="$key" -v v="$val" -F= '$1==k {print k "=" v; next} {print}' "$ENV_FILE" >"$tmp"
    else
        cat "$ENV_FILE" >"$tmp"
        printf '%s=%s\n' "$key" "$val" >>"$tmp"
    fi
    cat "$tmp" >"$ENV_FILE"   # ">" not "mv": keeps the original inode and mode
    rm -f "$tmp"
}

# The one host path that is NOT this deployment's alone. Every instance on the
# box bind-mounts it at the same absolute path (see the guacd service), so it is
# the one thing here that must survive a migration while somebody else is using
# it. Learned the hard way: deleting it out from under a running guacd leaves the
# container holding an unlinked inode, so every write fails with ENOENT and the
# only symptom is a log line nobody is reading.
SHARED_DESKTOP_DIR=/var/lib/guardrail/desktop-recordings

# other_instances lists compose projects on this host, other than ours, whose
# name marks them as GuardRail.
other_instances() {
    docker ps -a --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null |
        grep -E '^guardrail' | grep -vx "$PROJECT" | sort -u || true
}

profiles() {
    local -a p=()
    [ "$(env_get GUARDRAIL_DESKTOP_ENABLED)" = "true" ] && p+=(--profile desktop)
    if docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
        --format '{{.Names}}' 2>/dev/null | grep -q -- '-dns-'; then
        p+=(--profile dns)
    fi
    [ ${#p[@]} -gt 0 ] && printf '%s\n' "${p[@]}"
    return 0
}

# ---------------------------------------------------------------------------
# The four datasets
#
# Parallel arrays, indexed together. DS_VOL is the named volume a dataset lives
# in when its variable is unset; the desktop handover has none because it is a
# bind mount on both sides by design (see the guacd service in the compose file).
# ---------------------------------------------------------------------------
DS_LABEL=("PostgreSQL database" "Session recordings" "Redis cache" "Desktop handover")
DS_ENV=(GUARDRAIL_PGDATA_MOUNT GUARDRAIL_RECORDINGS_MOUNT GUARDRAIL_REDIS_MOUNT GUARDRAIL_GUACD_RECORDING_DIR)
DS_VOL=(pgdata recordings redisdata "")
DS_FALLBACK=("" "" "" /var/lib/guardrail/desktop-recordings)
DS_SUB=(postgres recordings redis desktop-recordings)
DS_OWN=("" 65532:65532 "" 1000:1000)
DS_MODE=("" "" "" 2770)
# The service and in-container path used to prove, after the restart, that the
# new location is the one actually in use. Empty means "no check available".
DS_SVC=(postgres api redis "")
DS_DEST=(/var/lib/postgresql/data /var/lib/guardrail/recordings /data "")

# resolve_source IDX -> SRC_KIND (volume|path|missing), SRC_PATH, SRC_VOL
resolve_source() {
    local i=$1 v mp
    SRC_KIND=""; SRC_PATH=""; SRC_VOL=""
    v=$(env_get "${DS_ENV[$i]}")
    if [ -n "$v" ] && [ "${v:0:1}" = "/" ]; then
        SRC_KIND=path; SRC_PATH="$v"
        [ -d "$SRC_PATH" ] || SRC_KIND=missing
        return 0
    fi
    if [ -n "${DS_VOL[$i]}" ]; then
        SRC_VOL="${PROJECT}_${DS_VOL[$i]}"
        mp=$(docker volume inspect -f '{{.Mountpoint}}' "$SRC_VOL" 2>/dev/null || true)
        if [ -n "$mp" ] && [ -d "$mp" ]; then SRC_KIND=volume; SRC_PATH="$mp"; return 0; fi
        SRC_KIND=missing; SRC_VOL=""
        return 0
    fi
    SRC_PATH="${DS_FALLBACK[$i]}"
    [ -d "$SRC_PATH" ] && SRC_KIND=path || SRC_KIND=missing
    return 0
}

show_layout() {
    step "Where the data lives now"
    local SRC_KIND SRC_PATH SRC_VOL
    local i
    for i in "${!DS_LABEL[@]}"; do
        resolve_source "$i"
        case "$SRC_KIND" in
            volume) printf '    %-22s %s\n        %s\n' "${DS_LABEL[$i]}" \
                        "${B}docker volume ${SRC_VOL}${R}" "${D}${SRC_PATH}${R}" ;;
            path)   printf '    %-22s %s\n' "${DS_LABEL[$i]}" "${B}${SRC_PATH}${R}" ;;
            missing) printf '    %-22s %s\n' "${DS_LABEL[$i]}" "${D}not created yet${R}" ;;
        esac
    done
    printf '\n    %-22s %s   %s\n' "configuration" "${B}${INSTALL_DIR}${R}" \
        "${D}(not moved by this script — back it up)${R}"
}

# ---------------------------------------------------------------------------
# Destination validation
#
# The failure this guards against is not a typo, it is a path that overlaps
# something already in play: a destination inside a source copies a directory
# into itself, and a destination under /var/lib/docker puts the data back in the
# place the operator is trying to leave — where a `docker system prune` can find
# it and a bind mount gives it none of a volume's protection.
# ---------------------------------------------------------------------------
validate_dest() { # validate_dest PATH
    # resolve_source reports through globals, and this walks every dataset to
    # test for overlap. Shadowing them keeps that a question rather than an
    # assignment: without these locals the caller's idea of "the current source"
    # silently becomes whichever dataset happened to be checked last.
    local SRC_KIND SRC_PATH SRC_VOL
    local d=$1 i
    case "$d" in
        /) err "refusing to use the filesystem root"; return 1 ;;
        /*) ;;
        *) err "give an absolute path, starting with /"; return 1 ;;
    esac
    case "$d" in
        /var/lib/docker | /var/lib/docker/*)
            err "that is inside Docker's own storage — pick a path outside /var/lib/docker"
            return 1 ;;
        "$INSTALL_DIR" | "$INSTALL_DIR"/*)
            err "that is inside ${INSTALL_DIR}, which install.sh deletes on Remove"
            return 1 ;;
    esac
    for i in "${!DS_LABEL[@]}"; do
        resolve_source "$i"
        [ "$SRC_KIND" = "missing" ] && continue
        case "$d" in
            "$SRC_PATH" | "$SRC_PATH"/*)
                err "that is inside the current ${DS_LABEL[$i]} location (${SRC_PATH})"
                return 1 ;;
        esac
    done
    if [ -e "$d" ] && [ ! -d "$d" ]; then
        err "${d} exists and is not a directory"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Copying
# ---------------------------------------------------------------------------
tree_bytes() { local n; n=$(du -sb "$1" 2>/dev/null | awk 'NR==1{print $1}'); printf '%s' "${n:-0}"; }

avail_bytes() { # avail_bytes PATH — walks up to the nearest existing ancestor
    local dir=$1
    while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do dir=$(dirname "$dir"); done
    df -B1 --output=avail "$dir" 2>/dev/null | tail -1 | tr -d ' '
}

copy_tree() { # copy_tree SRC DST
    local src=$1 dst=$2
    mkdir -p "$dst"
    # tar rather than `cp -a`: a Postgres data directory has hard links and
    # sparse files, and --numeric-owner keeps uid 70 as uid 70 across a
    # filesystem that has never heard of the container's passwd file.
    #
    # --sparse is not decoration. Without it tar reads a hole as zeros and writes
    # them out for real, so a migration silently inflates the data by however
    # much of it was a hole — measured here at 50MB written for a file allocating
    # nothing. The data is correct either way; the disk usage is not.
    tar -C "$src" --numeric-owner --sparse -cpf - . | tar -C "$dst" --numeric-owner -xpf -
}

# ---------------------------------------------------------------------------
# docker-compose.yml
#
# An install pinned to a release older than this feature has a compose file whose
# mounts are hardcoded names. Patch it in place rather than refusing: the operator
# came here to move their data, not to be told to upgrade first. The next update
# re-fetches the file from a ref that already has the variables, so the patch has
# to survive being reverted — which it does, because it is idempotent and the
# fetched file is equivalent.
# ---------------------------------------------------------------------------
compose_ready() { grep -q 'GUARDRAIL_PGDATA_MOUNT' "$COMPOSE_FILE"; }

patch_compose() {
    cp -a "$COMPOSE_FILE" "${COMPOSE_FILE}.bak"
    sed -i \
        -e 's|^\( *\)- pgdata:/var/lib/postgresql/data|\1- ${GUARDRAIL_PGDATA_MOUNT:-pgdata}:/var/lib/postgresql/data|' \
        -e 's|^\( *\)- redisdata:/data|\1- ${GUARDRAIL_REDIS_MOUNT:-redisdata}:/data|' \
        -e 's|^\( *\)- recordings:/var/lib/guardrail/recordings|\1- ${GUARDRAIL_RECORDINGS_MOUNT:-recordings}:/var/lib/guardrail/recordings|' \
        "$COMPOSE_FILE"

    local missing=""
    grep -q 'GUARDRAIL_PGDATA_MOUNT' "$COMPOSE_FILE"     || missing="$missing pgdata"
    grep -q 'GUARDRAIL_REDIS_MOUNT' "$COMPOSE_FILE"      || missing="$missing redis"
    grep -q 'GUARDRAIL_RECORDINGS_MOUNT' "$COMPOSE_FILE" || missing="$missing recordings"
    if [ -n "$missing" ] || ! compose config -q >/dev/null 2>&1; then
        cp -a "${COMPOSE_FILE}.bak" "$COMPOSE_FILE"
        err "could not rewrite the mounts in ${COMPOSE_FILE}${missing:+ (${missing# })}"
        err "the file was restored unchanged; update to 1.2.1 or newer and try again"
        return 1
    fi
    ok "docker-compose.yml updated ${D}(previous copy at ${COMPOSE_FILE}.bak)${R}"
}

# ---------------------------------------------------------------------------
# Stack control
# ---------------------------------------------------------------------------
# Set while the stack is deliberately down, so that an abort between the stop and
# the restart puts the deployment back up instead of leaving it dark. Every exit
# path out of do_relocate below runs through the trap on this.
STACK_DOWN=0

stop_stack() {
    # `stop`, not `down`: the containers keep existing, so a failed migration is
    # recovered by putting the variables back and starting them again. Both
    # profiles are named unconditionally — stopping a service that was never
    # started is a no-op, and missing one leaves it holding the data mid-copy.
    spin "stopping the stack" compose --profile dns --profile desktop stop
    STACK_DOWN=1
}

start_stack() {
    local -a prof=(); mapfile -t prof < <(profiles)
    # Mounts changed, so compose recreates the containers here rather than just
    # starting them — which is exactly what makes the new paths take effect.
    spin "starting the stack" compose "${prof[@]}" up -d --remove-orphans
    STACK_DOWN=0
}

wait_healthy() {
    local port tries=60
    port=$(env_get GUARDRAIL_HTTPS_PORT); port="${port:-443}"
    printf '  %s waiting for the API to answer' "${CYN}⠿${R}"
    while [ "$tries" -gt 0 ]; do
        if curl -fsk --max-time 3 "https://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
            printf '\r'; ok "API is healthy                        "
            return 0
        fi
        printf '.'; sleep 2; tries=$((tries - 1))
    done
    printf '\r'
    warn "the API did not answer in time — check: docker compose -p ${PROJECT} logs api"
    return 1
}

# mount_source SERVICE DESTPATH — what the running container has mounted there.
mount_source() {
    local cid
    cid=$(compose ps -q "$1" 2>/dev/null | head -1)
    [ -n "$cid" ] || return 1
    docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" "$cid" 2>/dev/null
}

# ---------------------------------------------------------------------------
# The migration itself
# ---------------------------------------------------------------------------
do_relocate() { # do_relocate move|copy
    local mode=$1 i dest total=0 avail sz
    local -a IDX=() FROM=() FROM_KIND=() FROM_VOL=() TO=()

    show_layout

    step "Destination"
    if [ "$mode" = "move" ]; then
        info "the data is moved there, the configuration is repointed, the stack restarts"
    else
        info "the data is copied there; the original is left exactly where it is"
    fi
    while true; do
        ask DATA_DIR "Directory to hold GuardRail's data" "${GUARDRAIL_DATA_DIR:-/srv/guardrail}"
        DATA_DIR="${DATA_DIR%/}"
        validate_dest "$DATA_DIR" && break
    done

    # ---- plan -------------------------------------------------------------
    for i in "${!DS_LABEL[@]}"; do
        resolve_source "$i"
        [ "$SRC_KIND" = "missing" ] && continue
        dest="$DATA_DIR/${DS_SUB[$i]}"
        if [ "$SRC_PATH" = "$dest" ]; then
            info "${DS_LABEL[$i]} is already at ${dest} — nothing to do"
            continue
        fi
        IDX+=("$i"); FROM+=("$SRC_PATH"); FROM_KIND+=("$SRC_KIND"); FROM_VOL+=("$SRC_VOL"); TO+=("$dest")
        total=$((total + $(tree_bytes "$SRC_PATH")))
    done

    if [ ${#IDX[@]} -eq 0 ]; then
        step "Nothing to do"
        info "every dataset is already where you asked for it"
        return 0
    fi

    step "Plan"
    for i in "${!IDX[@]}"; do
        sz=$(human "$(tree_bytes "${FROM[$i]}")")
        printf '    %-22s %s\n' "${DS_LABEL[${IDX[$i]}]}" "${D}${sz}${R}"
        printf '      from  %s%s\n' "${FROM[$i]}" \
            "$([ "${FROM_KIND[$i]}" = volume ] && printf '   %s' "${D}(volume ${FROM_VOL[$i]})${R}")"
        printf '      to    %s%s%s\n' "$B" "${TO[$i]}" "$R"
    done
    printf '\n    %-22s %s\n' "total to copy" "${B}$(human "$total")${R}"

    avail=$(avail_bytes "$DATA_DIR")
    printf '    %-22s %s\n' "free at destination" \
        "${B}$([ -n "$avail" ] && human "$avail" || echo "unknown")${R}"
    # 5% headroom: Postgres starts writing WAL the moment it comes back up, and a
    # destination that fits the copy exactly has no room for the database to run.
    if [ -n "$avail" ] && [ "$avail" -lt $((total + total / 20 + 104857600)) ]; then
        warn "that is tight — the database needs room to write once it restarts"
        local go
        ask_yn go "Continue anyway?" n
        [ "$go" = "yes" ] || { info "nothing changed"; return 0; }
    fi

    local repoint=yes
    if [ "$mode" = "copy" ]; then
        step "After the copy"
        ask_yn repoint "Point this deployment at the copy? ${D}(updates .env and docker-compose.yml)${R}" n
    fi

    step "Confirm"
    info "the stack will be STOPPED for the copy — sessions in progress will drop"
    [ "$mode" = "move" ] && warn "the original data is deleted once the stack is verified healthy at the new location"
    local go
    ask_yn go "Proceed?" n
    [ "$go" = "yes" ] || { info "nothing changed"; return 0; }

    # ---- copy -------------------------------------------------------------
    step "Copying"
    mkdir -p "$DATA_DIR"
    stop_stack
    for i in "${!IDX[@]}"; do
        spin "${DS_LABEL[${IDX[$i]}]} → ${TO[$i]}" copy_tree "${FROM[$i]}" "${TO[$i]}"
        # Ownership of the tree comes across in the archive; this fixes the top
        # directory for the case where it did not, so the service can still
        # create new files under it.
        local own="${DS_OWN[${IDX[$i]}]}" mode_bits="${DS_MODE[${IDX[$i]}]}"
        [ -n "$own" ] && chown "$own" "${TO[$i]}" 2>/dev/null || true
        [ -n "$mode_bits" ] && chmod "$mode_bits" "${TO[$i]}" 2>/dev/null || true
    done
    ok "copied $(human "$total")"

    # ---- repoint ----------------------------------------------------------
    if [ "$repoint" = "yes" ]; then
        step "Configuration"
        compose_ready || patch_compose || return 1
        for i in "${!IDX[@]}"; do
            env_set "${DS_ENV[${IDX[$i]}]}" "${TO[$i]}"
            info "${DS_ENV[${IDX[$i]}]}=${TO[$i]}"
        done
        ok "written to ${ENV_FILE}"
    else
        info "configuration left untouched — the deployment still uses the original data"
    fi

    # ---- restart ----------------------------------------------------------
    step "Restarting ${APP_NAME}"
    start_stack
    local healthy=yes
    wait_healthy || healthy=no

    # ---- verify -----------------------------------------------------------
    local verified=yes
    if [ "$repoint" = "yes" ]; then
        step "Verifying"
        for i in "${!IDX[@]}"; do
            local svc="${DS_SVC[${IDX[$i]}]}" cdest="${DS_DEST[${IDX[$i]}]}" actual=""
            [ -n "$svc" ] || continue
            actual=$(mount_source "$svc" "$cdest" || true)
            if [ "$actual" = "${TO[$i]}" ]; then
                ok "${svc} is reading ${DS_LABEL[${IDX[$i]}]} from ${TO[$i]}"
            else
                verified=no
                err "${svc} has ${cdest} mounted from ${actual:-nothing}, expected ${TO[$i]}"
            fi
        done
    fi

    # ---- finish -----------------------------------------------------------
    if [ "$mode" = "move" ]; then
        if [ "$verified" != "yes" ] || [ "$healthy" != "yes" ]; then
            step "Original data KEPT"
            err "the stack did not come up cleanly at the new location, so nothing was deleted"
            info "both copies exist. Investigate with: docker compose -p ${PROJECT} logs"
            info "to go back, clear these keys in ${ENV_FILE} and run: docker compose -p ${PROJECT} up -d"
            printf '\n'
            for i in "${!IDX[@]}"; do printf '      %s\n' "${DS_ENV[${IDX[$i]}]}="; done
            printf '\n'
            return 1
        fi
        step "Removing the originals"
        info "the stack is healthy and verified on the new location"
        local del
        ask_yn del "Delete the original data now? ${D}(irreversible)${R}" n
        if [ "$del" != "yes" ]; then
            print_leftovers
            return 0
        fi
        local others
        others=$(other_instances)
        for i in "${!IDX[@]}"; do
            if [ "${FROM_KIND[$i]}" = volume ]; then
                # Volumes are project-scoped by name, so this can only ever be ours.
                if docker volume rm "${FROM_VOL[$i]}" >/dev/null 2>&1; then
                    ok "removed volume ${FROM_VOL[$i]}"
                else
                    warn "could not remove volume ${FROM_VOL[$i]} — something still references it"
                fi
            elif [ "${FROM[$i]}" = "$SHARED_DESKTOP_DIR" ] && [ -n "$others" ]; then
                warn "kept ${FROM[$i]} — it is the shared default path and these"
                warn "instances on this host still bind-mount it: $(printf '%s ' $others)"
                info "your data was copied out of it; it is theirs now, not yours to delete"
            else
                rm -rf -- "${FROM[$i]}"
                ok "removed ${FROM[$i]}"
                # The parent exists only to hold this; leave it if it holds more.
                rmdir "$(dirname "${FROM[$i]}")" 2>/dev/null && \
                    info "removed the now-empty $(dirname "${FROM[$i]}")" || true
            fi
        done
        step "Done"
        ok "${APP_NAME}'s data now lives under ${B}${DATA_DIR}${R}"
    else
        step "Done"
        ok "copied to ${B}${DATA_DIR}${R}"
        print_leftovers
    fi

    printf '\n'
    info "back up ${B}${ENV_FILE}${R} as well — GUARDRAIL_MASTER_KEY decrypts the vault,"
    info "and a restored database without it is unreadable"
    return 0
}

# print_leftovers names the exact locations that are now redundant, using the
# arrays do_relocate has already populated. Deliberately verbose: this is the
# output someone acts on with rm -rf, and a wrong path there is unrecoverable.
print_leftovers() {
    local i
    if [ "${repoint:-yes}" != "yes" ]; then
        step "The copy — delete when you no longer want it"
        warn "the deployment is STILL USING its original location; this copy is the spare"
        info "nothing is reading it, so removing it changes nothing:"
        printf '\n      %s\n\n' "rm -rf -- ${DATA_DIR}"
        return 0
    fi
    step "The old data — delete when you are satisfied"
    info "nothing below is in use any more; the stack is running from ${DATA_DIR}"
    printf '\n'
    for i in "${!IDX[@]}"; do
        printf '    %s\n' "${B}${DS_LABEL[${IDX[$i]}]}${R}"
        if [ "${FROM_KIND[$i]}" = volume ]; then
            printf '      %s\n' "${D}on disk at ${FROM[$i]}${R}"
            printf '      %s\n' "docker volume rm ${FROM_VOL[$i]}"
        elif [ "${FROM[$i]}" = "$SHARED_DESKTOP_DIR" ] && [ -n "$(other_instances)" ]; then
            printf '      %s\n' "${YLW}leave this one alone${R} ${D}— ${FROM[$i]}${R}"
            printf '      %s\n' "${D}another instance on this host bind-mounts the same path${R}"
        else
            printf '      %s\n' "rm -rf -- ${FROM[$i]}"
        fi
    done
    printf '\n'
    info "verify the new location works first — log in, open a session, play a recording"
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
menu() {
    while true; do
        step "What would you like to do?"
        printf '    %s  Move %s\n' "${B}1${R}" \
            "${D}(relocate the data, repoint the config, restart, delete the original)${R}"
        printf '    %s  Copy %s\n' "${B}2${R}" \
            "${D}(duplicate the data, optionally repoint, tell you what to delete)${R}"
        printf '    %s  Exit\n\n' "${B}3${R}"
        local choice=""
        read_input choice "  Choice [1-3]: " || no_input
        case "$choice" in
            1) do_relocate move; return $? ;;
            2) do_relocate copy; return $? ;;
            3) info "nothing changed"; return 0 ;;
            *) warn "pick a number from 1 to 3" ;;
        esac
    done
}

cleanup() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ "$STACK_DOWN" = "1" ]; then
        printf '\n'
        warn "migration aborted with the stack stopped — bringing it back up"
        warn "nothing was deleted; the original data is where it was"
        docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" \
            --profile dns --profile desktop up -d >/dev/null 2>&1 || \
            err "could not restart it — run: docker compose -p ${PROJECT} up -d"
    fi
    exit "$rc"
}

main() {
    need_root
    have docker || die "Docker is not installed on this server"
    [ -f "$ENV_FILE" ] || die "no ${ENV_FILE} — is ${APP_NAME} installed? (set GUARDRAIL_DIR if it is elsewhere)"
    [ -f "$COMPOSE_FILE" ] || die "no ${COMPOSE_FILE} — is ${APP_NAME} installed?"
    setup_input
    trap cleanup EXIT

    printf '\n%s\n' "${B}${APP_NAME} — data migration${R}"
    printf '%s\n' "${D}project ${PROJECT}   ·   config ${INSTALL_DIR}${R}"

    menu
}

main "$@"
