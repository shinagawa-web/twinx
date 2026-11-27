#!/usr/bin/env bash
# Puts one run's measurements on the open pull request from a branch, or on the
# pull request $PR when given, in one comment that each later run replaces:
#   perf/lib/comment.sh <tag, or pr-<number> or ref-<ref>> <branch> [run URL]
#
# Reads perf/results/<arch>/<tag>.json for every architecture there. Does nothing
# when the branch has no open pull request.
set -euo pipefail
tag=${1:?usage: perf/lib/comment.sh <tag> <branch> [run URL]}
branch=${2:?usage: perf/lib/comment.sh <tag> <branch> [run URL]}
run=${3:-}
root=$(cd "$(dirname "$0")/.." && pwd)
marker='<!-- perf measurements -->'
# The commit measured: $COMMIT when given (a pull request's head), else this checkout's.
commit=$(git -C "$root" rev-parse --short "${COMMIT:-HEAD}" 2>/dev/null || echo "${COMMIT:0:7}")

pr=${PR:-$(gh pr list --head "$branch" --state open --json number -q '.[0].number')}
[ -n "$pr" ] || { echo "no open pull request from $branch"; exit 0; }

body=$(mktemp)
trap 'rm -f "$body"' EXIT
{
  echo "$marker"
  echo "## Measurements of twinx $tag against nginx"
  echo
  echo "From \`${commit}\`${run:+, [workflow run]($run)}. Measured on aarch64 runners, one for each group of scenarios measured; each cell is nginx / twinx. This comment is replaced by each run on this branch."
  found=
  for f in "$root"/results/*/"$tag".json; do
    [ -f "$f" ] || continue
    found=1
    echo
    kept=(); [ ! -f "$(dirname "$f")/nginx.json" ] || kept=(--nginx "$(dirname "$f")/nginx.json")
    python3 "$root/lib/compare.py" "$f" ${kept[@]+"${kept[@]}"}
  done
  [ -n "$found" ] || { echo; echo "No measurements were recorded for $tag."; }
} > "$body"

repo=$(gh repo view --json nameWithOwner -q .nameWithOwner)
id=$(gh api "repos/$repo/issues/$pr/comments" --paginate \
  -q ".[] | select(.body | startswith(\"$marker\")) | .id" | tail -1)
if [ -n "$id" ]; then
  gh api -X PATCH "repos/$repo/issues/comments/$id" -F body=@"$body" >/dev/null
  echo "replaced the measurements comment on #$pr"
else
  gh pr comment "$pr" --body-file "$body" >/dev/null
  echo "commented the measurements on #$pr"
fi
