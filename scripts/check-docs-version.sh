#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Documentation Consistency Check
# ============================================================================
# Fails when the published documentation disagrees with the workspace about
# the current version, or when the roadmap page stops mirroring ROADMAP.md.
#
# Usage: ./scripts/check-docs-version.sh [--fix]   (from anywhere)
#
#   (no flag)  report only; exits non-zero on any drift.
#   --fix      rewrite the "Current release" banners to the workspace version
#              before checking. The docs workflow runs this on every push to
#              main and commits the result, so the banners are machine-owned;
#              the remaining checks still only report, because they need a
#              human to write something.
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

FIX=0
if [[ "${1:-}" == "--fix" ]]; then
    FIX=1
elif [[ $# -gt 0 ]]; then
    echo "unknown argument: $1 (expected --fix or nothing)" >&2
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
if [[ $FIX -eq 1 ]]; then
    stale_files=$(grep -rln 'Current release: \*\*v' docs/ || true)
    while IFS= read -r doc; do
        [[ -n "$doc" ]] || continue
        sed -i "s/Current release: \*\*v[0-9]\+\.[0-9]\+\.[0-9]\+\*\*/Current release: **v${VERSION}**/g" "$doc"
    done <<< "$stale_files"
fi

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
# 2. The roadmap page must include ROADMAP.md instead of restating it.
# ---------------------------------------------------------------------------
if grep -q '^--8<-- "ROADMAP.md"$' docs/roadmap.md; then
    ok "docs/roadmap.md includes ROADMAP.md"
else
    fail "docs/roadmap.md no longer includes ROADMAP.md (expected a line: --8<-- \"ROADMAP.md\") — a hand-maintained copy will drift"
fi

if [[ ! -f ROADMAP.md ]]; then
    fail "ROADMAP.md is missing at the repository root; the docs build will fail"
fi

# ---------------------------------------------------------------------------
# 3. ROADMAP.md must carry a milestone for the current minor series.
# ---------------------------------------------------------------------------
series="v${VERSION%.*}.0"
if grep -q "^### .*${series}" ROADMAP.md; then
    ok "ROADMAP.md has a milestone for ${series}"
else
    fail "ROADMAP.md has no '### ... ${series}' milestone, but the workspace is on ${VERSION}"
fi

# ---------------------------------------------------------------------------
# 4. The changelog must mention the current minor series.
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
