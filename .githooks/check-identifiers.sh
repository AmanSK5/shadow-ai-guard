#!/usr/bin/env sh
# Fail if any input names a deployment this project is run against.
#
# Two callers, because the two halves leak differently:
#   check-identifiers.sh files            - tracked files, run in CI
#   check-identifiers.sh text <file>...   - commit messages, run by the hook
#
# The file check is the one CI can do. The text check is the one that
# matters most: CI never sees a commit message, and a message cannot be
# corrected later without rewriting history.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
list="$here/deny-list.txt"
if [ ! -f "$list" ]; then
  # No list configured. A fork has nothing of ours to protect, and a
  # check that invents patterns would only fail on other people's words.
  echo "check-identifiers: no $list; skipping (see deny-list.example.txt)" >&2
  exit 0
fi
patterns=$(grep -vE '^\s*(#|$)' "$list")
[ -n "$patterns" ] || exit 0
mode=${1:-files}
shift 2>/dev/null || true

status=0
report() {
  status=1
  echo "$1" >&2
}

case "$mode" in
  files)
    # Tracked files only: the working tree may hold a deployer's own
    # notes, and this is a check on what gets published.
    for p in $patterns; do
      hits=$(git grep -InEi -- "$p" -- \
               ':!.githooks/deny-list.example.txt' \
               ':!.githooks/check-identifiers.sh' \
               2>/dev/null || true)
      [ -n "$hits" ] && report "deployment identifier /$p/ in tracked files:
$hits"
    done
    ;;
  text)
    for f in "$@"; do
      [ -f "$f" ] || continue
      for p in $patterns; do
        hits=$(grep -InEi -- "$p" "$f" || true)
        [ -n "$hits" ] && report "deployment identifier /$p/ in $f:
$hits"
      done
    done
    ;;
  *)
    echo "usage: $0 [files|text <file>...]" >&2
    exit 2
    ;;
esac

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'

Describe the behaviour, not the estate it was seen in: "a live
deployment", "an asset-tagged serial (ASSET-<serial>)", "four figures of
findings in a week". What was observed is what makes a change worth
reading; where it was observed is not needed to make the point.

If a match is a false positive, narrow the pattern in the list rather
than skipping the check.
MSG
fi
exit "$status"
