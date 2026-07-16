#!/usr/bin/env bash
# Install the host packages GuardRail needs, and nothing else.
#
# bootstrap.sh deliberately refuses to install anything: it is about to hold the
# vault master key, and a script that silently apt-installs on the way there is
# not one you can audit at the moment it matters. This script is the other half —
# it installs, explicitly, only when you run it, and it never starts a service.
# Separating them keeps `install` honest: nothing is provisioned behind your back.
#
# It prints exactly what it will do and waits for a yes, unless given --yes.
#
# What it does NOT install: docker, go, node. Those have vendor installers with
# their own opinions about repos and keyrings, and piping them into a shell on a
# credential-holding host is the thing bootstrap.sh refuses to do. It tells you
# which are missing and where to get them.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -t 1 ]; then
    B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
    B=""; G=""; Y=""; R=""; D=""; N=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$B$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%serror:%s %s\n\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# go_ok reports whether the Go on this host is new enough to build the backend.
#
# Presence is not the question. Ubuntu 22.04 ships Go 1.18 as `go`, go.mod asks
# for 1.26, and 1.18 predates the toolchain directive that would fetch the right
# one — so it does not upgrade itself, it fails, and it fails as
# "package cmp is not in GOROOT", which reads like a broken install rather than
# an old compiler. Checking the version here turns that into one clear sentence.
GO_MIN_MAJOR=1
GO_MIN_MINOR=26
go_bin() {
    if have go; then command -v go
    elif [ -x /usr/local/go/bin/go ]; then echo /usr/local/go/bin/go
    fi
}
go_version() {
    local b; b=$(go_bin) || return 1
    [ -n "$b" ] || return 1
    "$b" version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}
go_ok() {
    local v; v=$(go_version) || return 1
    [ -n "$v" ] || return 1
    local maj="${v%%.*}" min="${v#*.}"
    [ "$maj" -gt "$GO_MIN_MAJOR" ] && return 0
    [ "$maj" -eq "$GO_MIN_MAJOR" ] && [ "$min" -ge "$GO_MIN_MINOR" ]
}

usage() {
    cat <<EOF
${B}GuardRail dependencies${N} — install host packages. Starts nothing.

  ${B}scripts/install-deps.sh${N} [options]

Options:
  --yes             Do not ask for confirmation.
  --dry-run         Print the commands, run none of them.
  --chromium=HOW    Where headless Chromium comes from:
                      ${B}auto${N}       per-distro default (below)
                      ${B}system${N}     the distro package manager
                      ${B}google${N}     Google Chrome from Google's apt repo (deb)
                      ${B}playwright${N} a private build under \$HOME, no root
                      ${B}skip${N}       leave it alone
  -h, --help        Show this.

${B}Why --chromium matters on Ubuntu.${N} Ubuntu ships no 'chromium' deb; the
'chromium-browser' package is a transitional stub that installs the Chromium
${B}snap${N}. The snap's confinement cannot read a --user-data-dir under /tmp, which
is exactly how GuardRail launches it, so isolation fails at Connect with a
browser that looks installed. On Ubuntu 'auto' therefore means ${B}google${N} (a real
deb) — or use ${B}playwright${N} if you would rather not add Google's repo.

Run it again any time; it is idempotent.
EOF
}

ASSUME_YES=0; DRY_RUN=0; CHROMIUM="auto"
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)      ASSUME_YES=1 ;;
        --dry-run)     DRY_RUN=1 ;;
        --chromium=*)  CHROMIUM="${1#*=}" ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage; die "unknown option: $1" ;;
    esac
    shift
done
case "$CHROMIUM" in
    auto|system|google|playwright|skip) ;;
    *) die "--chromium must be one of: auto, system, google, playwright, skip" ;;
esac

# --- who are we, and can we install ----------------------------------------
[ -r /etc/os-release ] || die "cannot read /etc/os-release; unsupported host"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO="${ID:-unknown}"; DISTRO_VER="${VERSION_ID:-}"
LIKE="${ID_LIKE:-}"

PKG=""
for p in apt-get dnf yum pacman zypper apk; do have "$p" && { PKG="$p"; break; }; done
[ -n "$PKG" ] || die "no supported package manager found (apt-get, dnf, yum, pacman, zypper, apk)"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    have sudo || die "not root and sudo is not installed; re-run this as root"
    SUDO="sudo"
fi

# run executes a command, or just shows it under --dry-run. Every mutation on the
# host goes through here, so --dry-run is a real guarantee and not a promise.
run() {
    printf '    %s$%s %s\n' "$D" "$N" "$*"
    [ "$DRY_RUN" -eq 1 ] && return 0
    "$@"
}

# --- what Chromium means here ----------------------------------------------
# Resolved before we print the plan, so the plan is the truth.
if [ "$CHROMIUM" = "auto" ]; then
    case "$DISTRO" in
        ubuntu)          CHROMIUM="google" ;;   # see usage(): the deb is a snap stub
        debian|raspbian) CHROMIUM="system" ;;   # Debian has a real chromium deb
        fedora|rhel|centos|rocky|almalinux|arch|manjaro|opensuse*|alpine) CHROMIUM="system" ;;
        *)
            case "$LIKE" in
                *debian*) CHROMIUM="system" ;;
                *fedora*|*rhel*|*suse*|*arch*) CHROMIUM="system" ;;
                *) CHROMIUM="playwright" ;;
            esac
            ;;
    esac
fi

# An existing browser is left alone: reinstalling it cannot help, and on Ubuntu a
# second one only makes autodetect's answer harder to predict.
EXISTING=""
for c in chromium chromium-browser google-chrome google-chrome-stable; do
    p=$(command -v "$c" 2>/dev/null) && { EXISTING="$p"; break; }
done
if [ -n "$EXISTING" ] && [ "$CHROMIUM" != "skip" ]; then
    warn "a browser is already installed: $EXISTING"
    info "leaving it as is; pass --chromium=skip to silence this, or remove it first"
    CHROMIUM="skip"
fi

# --- system packages --------------------------------------------------------
# openssl generates the .env secrets; python3 writes them in without tripping on
# a '/' in a base64 value; ca-certificates is what makes TLS verify at all.
BASE_PKGS=""
case "$PKG" in
    apt-get)        BASE_PKGS="openssl python3 ca-certificates curl" ;;
    dnf|yum)        BASE_PKGS="openssl python3 ca-certificates curl" ;;
    pacman)         BASE_PKGS="openssl python ca-certificates curl" ;;
    zypper)         BASE_PKGS="openssl python3 ca-certificates curl" ;;
    apk)            BASE_PKGS="openssl python3 ca-certificates curl" ;;
esac

SYS_CHROMIUM_PKG=""
if [ "$CHROMIUM" = "system" ]; then
    case "$PKG" in
        apt-get)  SYS_CHROMIUM_PKG="chromium" ;;
        dnf|yum)  SYS_CHROMIUM_PKG="chromium" ;;
        pacman)   SYS_CHROMIUM_PKG="chromium" ;;
        zypper)   SYS_CHROMIUM_PKG="chromium" ;;
        apk)      SYS_CHROMIUM_PKG="chromium" ;;
    esac
fi

# --- the plan ---------------------------------------------------------------
step "Plan for ${B}${PRETTY_NAME:-$DISTRO $DISTRO_VER}${N}"
info "package manager: $PKG${SUDO:+   (via sudo)}"
info ""
info "${B}install:${N} $BASE_PKGS"
case "$CHROMIUM" in
    system)     info "${B}chromium:${N} $SYS_CHROMIUM_PKG (distro package)" ;;
    google)     info "${B}chromium:${N} google-chrome-stable, adding Google's apt repo + signing key" ;;
    playwright) info "${B}chromium:${N} private build under \$HOME via npx playwright (no root)" ;;
    skip)       info "${B}chromium:${N} skipped" ;;
esac
info ""
info "${D}nothing is started; run 'make install' when this finishes${N}"

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf '\n    Proceed? [y/N] '
    read -r reply </dev/tty || die "no tty to ask on; re-run with --yes"
    case "$reply" in [yY]*) ;; *) info "nothing done"; exit 0 ;; esac
fi

# --- install ----------------------------------------------------------------
step "Base packages"
case "$PKG" in
    apt-get)
        run $SUDO apt-get update
        # shellcheck disable=SC2086
        run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y $BASE_PKGS
        ;;
    dnf|yum)  run $SUDO "$PKG" install -y $BASE_PKGS ;;
    pacman)   run $SUDO pacman -Sy --noconfirm $BASE_PKGS ;;
    zypper)   run $SUDO zypper install -y $BASE_PKGS ;;
    apk)      run $SUDO apk add --no-cache $BASE_PKGS ;;
esac

CHROME_PATH=""
case "$CHROMIUM" in
    system)
        step "Chromium (distro package)"
        # Ubuntu's 'chromium' does not exist and 'chromium-browser' is a snap stub,
        # which is why auto never routes Ubuntu here. Guard it anyway: someone will
        # pass --chromium=system on Ubuntu and deserves the reason, not a 404.
        if [ "$PKG" = "apt-get" ] && [ "$DISTRO" = "ubuntu" ]; then
            die "Ubuntu has no 'chromium' deb — 'chromium-browser' installs the snap,
    whose confinement cannot read the --user-data-dir GuardRail passes.
    Use --chromium=google (a real deb) or --chromium=playwright instead."
        fi
        case "$PKG" in
            apt-get)  run $SUDO apt-get update
                      run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$SYS_CHROMIUM_PKG" ;;
            dnf|yum)  run $SUDO "$PKG" install -y "$SYS_CHROMIUM_PKG" ;;
            pacman)   run $SUDO pacman -Sy --noconfirm "$SYS_CHROMIUM_PKG" ;;
            zypper)   run $SUDO zypper install -y "$SYS_CHROMIUM_PKG" ;;
            apk)      run $SUDO apk add --no-cache "$SYS_CHROMIUM_PKG" ;;
        esac
        CHROME_PATH="$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || true)"
        ;;

    google)
        step "Google Chrome (deb, from Google's apt repo)"
        [ "$PKG" = "apt-get" ] || die "--chromium=google needs apt; use --chromium=system or =playwright"
        # The key goes in its own keyring and the repo is pinned to it by
        # signed-by, so this repo can never vouch for anything else on the host.
        run $SUDO install -d -m 0755 /usr/share/keyrings
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '    %s$%s curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor | %s tee /usr/share/keyrings/google-chrome.gpg\n' "$D" "$N" "$SUDO"
        else
            curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
                | gpg --dearmor \
                | $SUDO tee /usr/share/keyrings/google-chrome.gpg >/dev/null \
                || die "could not fetch Google's signing key"
            $SUDO chmod 0644 /usr/share/keyrings/google-chrome.gpg
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '    %s$%s echo "deb [signed-by=...] http://dl.google.com/linux/chrome/deb/ stable main" | %s tee /etc/apt/sources.list.d/google-chrome.list\n' "$D" "$N" "$SUDO"
        else
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
                | $SUDO tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
        fi
        run $SUDO apt-get update
        run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y google-chrome-stable
        CHROME_PATH="$(command -v google-chrome-stable 2>/dev/null || command -v google-chrome 2>/dev/null || true)"
        ;;

    playwright)
        step "Chromium (private build under \$HOME)"
        have npx || die "npx not found; install node + npm first — https://nodejs.org/"
        # --with-deps needs root to apt-get the shared libraries the browser links
        # against; without root we install the browser alone and let the launch
        # tell us if a library is missing.
        if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
            run npx --yes playwright@latest install --with-deps chromium
        else
            run npx --yes playwright@latest install chromium
        fi
        if [ "$DRY_RUN" -eq 0 ]; then
            CHROME_PATH=$(ls -d "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | sort -r | head -1 || true)
        fi
        ;;

    skip)
        step "Chromium"
        info "skipped${EXISTING:+ — already present at $EXISTING}"
        CHROME_PATH="$EXISTING"
        ;;
esac

# --- what we could not install ---------------------------------------------
step "Prerequisites this script will not install"
missing=()
have docker || missing+=("docker            — https://docs.docker.com/engine/install/")
if have docker && ! docker compose version >/dev/null 2>&1; then
    missing+=("docker compose v2 — the 'compose' plugin for docker")
fi
have npm || missing+=("node + npm        — https://nodejs.org/  (needed to build the console)")
if ! go_ok; then
    have_v=$(go_version 2>/dev/null || true)
    if [ -n "$have_v" ]; then
        missing+=("go ${GO_MIN_MAJOR}.${GO_MIN_MINOR}+          — https://go.dev/dl/  (found go${have_v}, too old to build go.mod)")
    else
        missing+=("go ${GO_MIN_MAJOR}.${GO_MIN_MINOR}+          — https://go.dev/dl/  (only for 'make install-native')")
    fi
fi
if [ ${#missing[@]} -gt 0 ]; then
    for m in "${missing[@]}"; do warn "$m"; done
    info ""
    info "These have vendor installers with their own repo and keyring opinions, so"
    info "this script leaves them to you rather than piping one into a shell."
else
    info "docker, compose, node, go — all present"
fi

# --- tell the operator the one thing they must do ---------------------------
step "Done"
if [ -n "$CHROME_PATH" ]; then
    info "browser: ${B}${CHROME_PATH}${N}"
    # Autodetect scans $PATH for chromium/chromium-browser/google-chrome. A
    # playwright build is under $HOME and on nobody's PATH, so that one must be
    # pinned or the API will look installed and still refuse at Connect.
    case "$CHROME_PATH" in
        "$HOME"/.cache/*)
            warn "this build is not on \$PATH, so autodetect will not find it."
            info "pin it in .env:"
            info "  ${B}GUARDRAIL_CHROME_PATH=${CHROME_PATH}${N}"
            ;;
        *)
            info "${D}on \$PATH — GuardRail autodetects it; GUARDRAIL_CHROME_PATH can stay blank${D}${N}"
            ;;
    esac
elif [ "$DRY_RUN" -eq 1 ]; then
    info "${D}(dry run — nothing installed, so no path to report)${N}"
elif [ "$CHROMIUM" != "skip" ]; then
    warn "no browser path resolved — check the output above"
fi
info ""
info "next: ${B}make install${N}   ${D}(or 'make install-native' to reach LAN devices)${N}"
