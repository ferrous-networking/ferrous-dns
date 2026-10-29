#!/usr/bin/env bash

# ============================================================================
# Ferrous DNS - Release Milestone
# ============================================================================
# Files a release under its milestone and closes it, so a closed milestone
# lists what its release shipped. Every pull request merged since the previous
# tag, and every issue it closes, is set to the milestone titled vX.Y.Z (or
# "vX.Y.Z — …"), whatever milestone it had before. Issues and pull requests
# still open in it move to the next open milestone by version. A release with
# no milestone gets one. The release notes on GitHub gain a link to it.
# release.yml runs it once the release and its binaries are published.
#
# Usage: ./scripts/release-milestone.sh vX.Y.Z [REF] [--dry-run]
#   REF        the commit the release is cut from (default: the tag)
#   --dry-run  only reads, and prints what it would change
#
# Needs gh, with write access to issues, pull requests and releases.
# Safe to run again: whatever is already in place is left alone.
# ============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

dry_run=false
args=()
for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=true ;;
        *) args+=("$arg") ;;
    esac
done
if [[ ${#args[@]} -lt 1 || ${#args[@]} -gt 2 || ! "${args[0]}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 vX.Y.Z [REF] [--dry-run]" >&2
    exit 2
fi
tag="${args[0]}"
ref="${args[1]:-$tag}"
repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

# Every write goes through here, so a dry run changes nothing.
write() {
    if ! $dry_run; then
        gh "$@" > /dev/null
    fi
}

# Prints one change, marked when it was not made.
report() {
    if $dry_run; then
        echo "- (dry run) $*"
    else
        echo "- $*"
    fi
}

# True when version $1 sorts after version $2.
newer_than() {
    [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$1" ]]
}

if prev=$(git describe --tags --abbrev=0 --match 'v*.*.*' "${ref}^" 2> /dev/null); then
    range="${prev}..${ref}"
else
    prev="the first commit"
    range="$ref"
fi
# Squash-merged pull requests end their subject with "(#N)".
mapfile -t prs < <(git log --format=%s "$range" | sed -nE 's/.*\(#([0-9]+)\)$/\1/p')

# number, state, title and URL of every milestone; titles hold no tabs.
milestones=$(gh api --paginate "repos/${repo}/milestones?state=all&per_page=100" \
    --jq '.[] | [.number, .state, .title, .html_url] | @tsv')
milestone=$(awk -F'\t' -v t="$tag" '$3 == t || index($3, t " ") == 1' <<< "$milestones" | head -n 1)

if [[ -n "$milestone" ]]; then
    IFS=$'\t' read -r number state title url <<< "$milestone"
else
    title="$tag"
    state=open
    if $dry_run; then
        number=""
        url=""
    else
        IFS=$'\t' read -r number url < <(gh api --method POST "repos/${repo}/milestones" \
            -f title="$tag" --jq '[.number, .html_url] | @tsv')
    fi
fi

echo "Release ${tag}: ${#prs[@]} pull requests since ${prev}, milestone ${title}."
[[ -z "$milestone" ]] && report "created milestone ${title}"

# Each pull request, then each issue it closes, as "number<TAB>milestone".
if [[ ${#prs[@]} -gt 0 ]]; then
    query="query { repository(owner: \"${repo%/*}\", name: \"${repo#*/}\") {"
    for pr in "${prs[@]}"; do
        query+=" p${pr}: pullRequest(number: ${pr}) { number milestone { title }"
        query+=" closingIssuesReferences(first: 20) { nodes { number milestone { title } } } }"
    done
    query+=" } }"
    items=$(gh api graphql -f query="$query" --jq '
        .data.repository[]
        | ([.number, (.milestone.title // "")] | @tsv),
          (.closingIssuesReferences.nodes[] | [.number, (.milestone.title // "")] | @tsv)' |
        sort -t $'\t' -k1,1n -u)
else
    items=""
fi

already=0
while IFS=$'\t' read -r item current; do
    [[ -z "$item" ]] && continue
    if [[ "$current" == "$title" ]]; then
        already=$((already + 1))
        continue
    fi
    write api --method PATCH "repos/${repo}/issues/${item}" -F milestone="$number"
    report "#${item}: ${current:-no milestone} → ${title}"
done <<< "$items"
echo "${already} already in ${title}."

# Whatever is still open was planned here but did not ship.
open_items=""
if [[ -n "$number" ]]; then
    open_items=$(gh api --paginate "repos/${repo}/issues?milestone=${number}&state=open&per_page=100" \
        --jq '.[].number')
fi
next=$(while IFS=$'\t' read -r n s t _; do
    v="${t%% *}"
    if [[ "$s" == open && "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && newer_than "$v" "$tag"; then
        printf '%s\t%s\t%s\n' "$v" "$n" "$t"
    fi
done <<< "$milestones" | sort -V | head -n 1)

close=true
if [[ -n "$open_items" && -z "$next" ]]; then
    echo "::warning::${title} still has open items and no later milestone to move them to, so it stays open."
    close=false
elif [[ -n "$open_items" ]]; then
    IFS=$'\t' read -r _ next_number next_title <<< "$next"
    for item in $open_items; do
        write api --method PATCH "repos/${repo}/issues/${item}" -F milestone="$next_number"
        report "#${item} is still open: ${title} → ${next_title}"
    done
fi

if $close && [[ "$state" != closed ]]; then
    if [[ -n "$number" ]]; then
        write api --method PATCH "repos/${repo}/milestones/${number}" -f state=closed
    fi
    report "closed ${title}"
fi

# The notes come from CHANGELOG.md; only the GitHub release links the milestone.
if ! notes=$(gh release view "$tag" --json body --jq .body 2> /dev/null); then
    echo "No ${tag} release on GitHub yet, so its notes are left alone."
elif [[ -n "$url" && "$notes" == *"$url"* ]]; then
    echo "The ${tag} release notes already link ${title}."
else
    if ! $dry_run; then
        notes_file=$(mktemp)
        printf '%s\n\n**Milestone:** [%s](%s)\n' "$notes" "$title" "$url" > "$notes_file"
        gh release edit "$tag" --notes-file "$notes_file" > /dev/null
        rm -f "$notes_file"
    fi
    report "linked ${title} in the ${tag} release notes"
fi
