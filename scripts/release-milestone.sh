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
# Needs gh, with write access to issues, pull requests and releases, and the
# tags fetched. Safe to run again: whatever is already in place is left alone.
# Exits 2 on bad usage, and non-zero when REF or the previous tag is missing,
# the range holds no pull request, or a gh call fails.
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

# Every change goes through here: it is printed, and made unless this is a dry
# run. The message goes to fd 3, so a caller can capture the command's output.
exec 3>&1
apply() {
    local message="$1"
    shift
    if $dry_run; then
        echo "- (dry run) ${message}" >&3
    else
        "$@" || return
        echo "- ${message}" >&3
    fi
}

# True when version $1 sorts after version $2.
newer_than() {
    [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$1" ]]
}

if ! git rev-parse -q --verify "${ref}^{commit}" > /dev/null; then
    echo "${ref} is not a commit here; fetch it, or the tag, first" >&2
    exit 1
fi
# Without the previous tag the range would be the whole history.
if ! prev=$(git describe --tags --abbrev=0 --match 'v*.*.*' --exclude '*-*' "${ref}^" 2> /dev/null); then
    echo "no vX.Y.Z tag before ${ref}; fetch the tags (git fetch --tags) first" >&2
    exit 1
fi
# Squash-merged pull requests end their subject with "(#N)".
prs=$(git log --format=%s "${prev}..${ref}" | sed -nE 's/.*\(#([0-9]+)\)$/\1/p')
if [[ -z "$prs" ]]; then
    echo "no pull request between ${prev} and ${ref}" >&2
    exit 1
fi

# number, state, title and URL of every milestone; titles hold no tabs.
milestones=$(gh api --paginate "repos/${repo}/milestones?state=all&per_page=100" \
    --jq '.[] | [.number, .state, .title, .html_url] | @tsv')
milestone=$(awk -F'\t' -v t="$tag" '$3 == t || index($3, t " ") == 1' <<< "$milestones" | head -n 1)

if [[ -n "$milestone" ]]; then
    IFS=$'\t' read -r number state title url <<< "$milestone"
    echo "Release ${tag}: $(wc -l <<< "$prs") pull requests since ${prev}, milestone ${title}."
else
    title="$tag"
    state=open
    echo "Release ${tag}: $(wc -l <<< "$prs") pull requests since ${prev}, milestone ${title}."
    created=$(apply "created milestone ${title}" gh api --method POST "repos/${repo}/milestones" \
        -f title="$tag" --jq '[.number, .html_url] | @tsv')
    IFS=$'\t' read -r number url <<< "$created"
fi

# Each pull request, then each issue in this repository it closes, as
# "number<TAB>milestone". A "(#N)" that names an issue yields nothing.
query="query { repository(owner: \"${repo%/*}\", name: \"${repo#*/}\") {"
for pr in $prs; do
    query+=" p${pr}: issueOrPullRequest(number: ${pr}) { ... on PullRequest { number milestone { title }"
    query+=" closingIssuesReferences(first: 50) { nodes { number repository { nameWithOwner } milestone { title } } } } }"
done
query+=" } }"
items=$(gh api graphql -f query="$query" --jq '
    .data.repository[] | select(.number != null)
    | ([.number, (.milestone.title // "")] | @tsv),
      (.closingIssuesReferences.nodes[]
       | select((.repository.nameWithOwner | ascii_downcase) == ("'"$repo"'" | ascii_downcase))
       | [.number, (.milestone.title // "")] | @tsv)' |
    sort -t $'\t' -k1,1n -u)

already=0
while IFS=$'\t' read -r item current; do
    [[ -z "$item" ]] && continue
    if [[ "$current" == "$title" ]]; then
        already=$((already + 1))
        continue
    fi
    apply "#${item}: ${current:-no milestone} → ${title}" \
        gh api --method PATCH "repos/${repo}/issues/${item}" -F milestone="$number" > /dev/null
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
    echo "::warning::${title} still has open items and no later milestone to move them to, so it stays open." >&2
    close=false
elif [[ -n "$open_items" ]]; then
    IFS=$'\t' read -r _ next_number next_title <<< "$next"
    for item in $open_items; do
        apply "#${item} is still open: ${title} → ${next_title}" \
            gh api --method PATCH "repos/${repo}/issues/${item}" -F milestone="$next_number" > /dev/null
    done
fi

if $close && [[ "$state" != closed ]]; then
    apply "closed ${title}" \
        gh api --method PATCH "repos/${repo}/milestones/${number}" -f state=closed > /dev/null
fi

# The notes come from CHANGELOG.md; only the GitHub release links the milestone.
errors=$(mktemp)
notes_file=$(mktemp)
trap 'rm -f "$errors" "$notes_file"' EXIT
if ! notes=$(gh release view "$tag" --repo "$repo" --json body --jq .body 2> "$errors"); then
    if ! grep -q 'release not found' "$errors"; then
        cat "$errors" >&2
        exit 1
    fi
    echo "No ${tag} release on GitHub yet, so its notes are left alone."
elif [[ -n "$url" && "$notes" == *"](${url})"* ]]; then
    echo "The ${tag} release notes already link ${title}."
else
    printf '%s\n\n**Milestone:** [%s](%s)\n' "$notes" "$title" "$url" > "$notes_file"
    apply "linked ${title} in the ${tag} release notes" \
        gh release edit "$tag" --repo "$repo" --notes-file "$notes_file" > /dev/null
fi
