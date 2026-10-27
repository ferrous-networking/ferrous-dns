#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Documentation Consistency Check
# ============================================================================
# Fails when the published documentation disagrees with the workspace about
# the current version: a stale "Current release" banner, or no changelog entry
# for the current minor series.
#
# Usage: ./scripts/check-docs-version.sh   (from anywhere)
#
# Report only; exits non-zero on any drift. The "Current release" banners are
# rewritten by scripts/bump-version.sh inside the release pull request, so on
# any other branch they already match Cargo.toml.
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -gt 0 ]]; then
    echo "unknown argument: $1 (this script takes none)" >&2
    exit 2
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

status=0

fail() {
    echo -e "${RED}✗${NC} $1"
    status=1
}

ok() {
    echo -e "${GREEN}✓${NC} $1"
}

VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
if [[ -z "$VERSION" ]]; then
    fail "could not read the workspace version from Cargo.toml"
    exit 1
fi
echo "Workspace version: $VERSION"

# ---------------------------------------------------------------------------
# 1. Every "Current release" banner must name the workspace version.
# ---------------------------------------------------------------------------
banners=$(grep -rn 'Current release: \*\*v' docs/ || true)
if [[ -z "$banners" ]]; then
    fail "no 'Current release: **vX.Y.Z**' banner found under docs/ — the docs no longer state which version they describe"
else
    stale=$(printf '%s\n' "$banners" | grep -v "Current release: \*\*v${VERSION}\*\*" || true)
    if [[ -n "$stale" ]]; then
        fail "documentation states a version other than ${VERSION}:"
        printf '%s\n' "$stale" | sed 's/^/    /'
    else
        ok "$(printf '%s\n' "$banners" | wc -l) version banner(s) match Cargo.toml"
    fi
fi

# ---------------------------------------------------------------------------
# 2. The changelog must mention the current minor series.
# ---------------------------------------------------------------------------
if grep -q "v${VERSION%.*}" docs/changelog.md; then
    ok "docs/changelog.md mentions the v${VERSION%.*} series"
else
    fail "docs/changelog.md has no entry for the v${VERSION%.*} series"
fi

echo ""
if [[ $status -eq 0 ]]; then
    echo -e "${GREEN}Documentation is consistent with the workspace.${NC}"
else
    echo -e "${RED}Documentation is out of sync — fix the items above.${NC}"
fi

exit $status
