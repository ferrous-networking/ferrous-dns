#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Release Notes
# ============================================================================
# Prints one release's section of CHANGELOG.md: its `## [X.Y.Z]` heading and
# everything up to the previous release. release-pr.yml shows it in the release
# pull request and release.yml publishes it, so both show the same text.
#
# Usage: ./scripts/changelog-section.sh vX.Y.Z   (or X.Y.Z; from anywhere)
#
# Exits non-zero when the section is missing or lists no changes.
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -ne 1 ]]; then
    echo "usage: $0 vX.Y.Z" >&2
    exit 2
fi

version="${1#v}"
section=$(awk -v v="$version" '
    index($0, "## [" v "]") == 1 { found = 1; print; next }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md)

if ! grep -q '^### ' <<< "$section"; then
    echo "CHANGELOG.md lists no changes for ${version}" >&2
    exit 1
fi

printf '%s\n' "$section"
