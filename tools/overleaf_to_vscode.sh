#!/usr/bin/env bash
# One-way: Overleaf -> local latex/SUIT_SEC@SAC. Does not need latex/ to be tracked.
# Files whose content differs locally are saved as *.local~ before being
# overwritten; nothing is deleted locally. Use --dry-run to only list what would change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DEST="latex/SUIT_SEC@SAC"
CACHE=".git/overleaf-sac-cache"          # bare mirror of the Overleaf project
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
DRY=; [ "${1:-}" = "--dry-run" ] && DRY=1

[ -d "$CACHE" ] || git init -q --bare "$CACHE"
git --git-dir="$CACHE" fetch -q "$(git remote get-url overleaf-sac)" +main:refs/heads/main
git --git-dir="$CACHE" archive main | tar -x -C "$WORK"

# --checksum compares content: git archive stamps every file with the commit
# time, so the default size+mtime check would rewrite (and back up) every file.
OPTS=(-rtv --checksum --backup --suffix=.local~ --itemize-changes)
[ -n "$DRY" ] && OPTS+=(--dry-run)
rsync "${OPTS[@]}" "$WORK"/ "$DEST"/

# Record the Overleaf version the local copy now contains; vscode_to_overleaf.sh
# refuses to push while Overleaf is ahead of it.
[ -n "$DRY" ] || git --git-dir="$CACHE" update-ref refs/heads/synced main
echo "Overleaf $(git --git-dir="$CACHE" rev-parse --short main) -> $DEST${DRY:+ (dry run)}"
