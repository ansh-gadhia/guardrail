#!/usr/bin/env bash
# GuardRail — cut a release.
#
# The version lives in more than one place and always will: the VERSION file is
# the source of truth, but scripts/install.sh carries a default so that
# `curl … | sudo bash` works with no checkout, and CHANGELOG.md has to name the
# version it is describing. Three files that must agree, updated by hand, is a
# guarantee they will not — which is what happened here: VERSION reached 1.2.0
# while the changelog still had every change since 1.0.0 sitting under
# [Unreleased], so 1.1.x and 1.2.0 shipped with no record of what was in them.
#
#   scripts/release.sh minor          bump 1.2.0 -> 1.3.0 and date the changelog
#   scripts/release.sh 2.0.0          set an explicit version
#   scripts/release.sh --check        verify the files agree (used by CI)
#
# It writes files and stops. Committing, tagging and pushing stay manual,
# because those are the steps that reach other people.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

B=$'\033[1m'; R=$'\033[0m'; D=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
die() { printf '%s\n' "${RED}error:${R} $*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }

VERSION_FILE=VERSION
INSTALLER=scripts/install.sh
CHANGELOG=CHANGELOG.md

current() { tr -d ' \n' < "$VERSION_FILE"; }

# The installer's fallback, which is what a no-checkout install pins to.
installer_version() {
    sed -n 's/^VERSION="${GUARDRAIL_VERSION:-\(.*\)}"$/\1/p' "$INSTALLER" | head -1
}

check() {
    local v i rc=0
    v=$(current); i=$(installer_version)
    printf '  %-28s %s\n' "VERSION" "$v"
    printf '  %-28s %s\n' "$INSTALLER" "${i:-<not found>}"
    if [ "$v" != "$i" ]; then
        printf '%s\n' "${RED}  they disagree — a no-checkout install would pin ${i}, not ${v}${R}"
        rc=1
    fi
    if ! grep -q "^## \[${v}\] - " "$CHANGELOG"; then
        printf '%s\n' "${RED}  CHANGELOG.md has no released section for ${v}${R}"
        printf '%s\n' "${D}  everything since the last release is still under [Unreleased]${R}"
        rc=1
    fi
    [ "$rc" -eq 0 ] && printf '%s\n' "${GRN}  version files agree${R}"
    return "$rc"
}

# unreleased_body prints what currently sits under [Unreleased].
unreleased_body() {
    awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f' "$CHANGELOG"
}

bump() {
    local part=$1 cur major minor patch
    cur=$(current)
    IFS=. read -r major minor patch <<<"$cur"
    case "$part" in
        major) echo "$((major+1)).0.0" ;;
        minor) echo "${major}.$((minor+1)).0" ;;
        patch) echo "${major}.${minor}.$((patch+1))" ;;
        *)     echo "$part" ;;
    esac
}

[ $# -eq 1 ] || { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

if [ "$1" = "--check" ]; then check; exit $?; fi

NEW=$(bump "$1")
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "not a semantic version: $NEW"
CUR=$(current)
[ "$NEW" != "$CUR" ] || die "$NEW is already the current version"
grep -q "^## \[${NEW}\] - " "$CHANGELOG" && die "CHANGELOG.md already has a section for $NEW"

# A release with nothing in it is a version number nobody can explain later.
[ -n "$(unreleased_body | tr -d '[:space:]')" ] || die "nothing under [Unreleased] — no changes to release"

DATE=$(date -u +%Y-%m-%d)
printf '%s\n' "${B}Releasing ${CUR} -> ${NEW}${R} ${D}(${DATE})${R}"

printf '%s\n' "$NEW" > "$VERSION_FILE"
info "VERSION -> $NEW"

# The installer's default has to move with it, or a fresh no-checkout install
# silently pins the previous release.
tmp=$(mktemp)
sed "s|^VERSION=\"\${GUARDRAIL_VERSION:-.*}\"$|VERSION=\"\${GUARDRAIL_VERSION:-${NEW}}\"|" "$INSTALLER" > "$tmp"
cat "$tmp" > "$INSTALLER"; rm -f "$tmp"
[ "$(installer_version)" = "$NEW" ] || die "could not update the version in $INSTALLER"
info "$INSTALLER -> $NEW"

# [Unreleased] stays at the top and empty; what was under it becomes the new
# dated section directly beneath.
tmp=$(mktemp)
awk -v ver="$NEW" -v date="$DATE" '
    /^## \[Unreleased\]/ && !done {
        print "## [Unreleased]"
        print ""
        print "## [" ver "] - " date
        done = 1
        next
    }
    { print }
' "$CHANGELOG" > "$tmp"
cat "$tmp" > "$CHANGELOG"; rm -f "$tmp"
info "CHANGELOG.md -> [${NEW}] - ${DATE}"

printf '\n%s\n' "${B}Next${R}"
printf '  %s\n' "git add -A && git commit -m 'GuardRail ${NEW}'"
printf '  %s\n' "git tag -a v${NEW} -m 'GuardRail ${NEW}'"
printf '  %s\n' "${D}push when you are ready; CI publishes :${NEW}, :latest and an immutable :sha-<commit>${R}"
