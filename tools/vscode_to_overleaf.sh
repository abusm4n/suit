#!/usr/bin/env bash
# One-way: local latex/SUIT_SEC@SAC -> Overleaf, as one new commit on top of
# Overleaf's head (no force, no merge). Does not need latex/ to be tracked.
# Refuses to run while Overleaf has edits that overleaf_to_vscode.sh has not
# brought in yet, so co-authors' changes are never overwritten.
# Pushes changed files and new .tex/.bib/figure files; never deletes a file on
# Overleaf; build output, notes and *.local~ backups stay local.
# Use --dry-run to only list what would change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DEST="latex/SUIT_SEC@SAC"
CACHE=".git/overleaf-sac-cache"          # bare mirror of the Overleaf project
URL=$(git remote get-url overleaf-sac)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
DRY=; [ "${1:-}" = "--dry-run" ] && DRY=1
og() { git --git-dir="$CACHE" "$@"; }

[ -d "$CACHE" ] || { echo "Run tools/overleaf_to_vscode.sh first." >&2; exit 1; }
og fetch -q "$URL" +main:refs/heads/main
if [ "$(og rev-parse -q --verify synced || true)" != "$(og rev-parse main)" ]; then
  echo "Overleaf has changes that are not in $DEST yet." >&2
  echo "Run tools/overleaf_to_vscode.sh, merge any *.local~ backups, then retry." >&2
  exit 1
fi

# Tree = Overleaf's files, overlaid with the local versions of those files
# (removed ones are kept) plus new local sources and figures.
export GIT_INDEX_FILE="$WORK/index"
og read-tree main
{ og ls-files -z | while IFS= read -r -d '' f; do
    [ -f "$DEST/$f" ] && printf '%s\0' "$f"
  done
  (cd "$DEST" && find . -type f \( -name '*.tex' -o -name '*.bib' -o -path './fig/*' \) \
     ! -name '*.local~' -printf '%P\0')
} | og --literal-pathspecs --work-tree="$DEST" add -f --pathspec-from-file=- --pathspec-file-nul
tree=$(og write-tree)

if [ "$tree" = "$(og rev-parse 'main^{tree}')" ]; then
  echo "Nothing to push: $DEST matches Overleaf $(og rev-parse --short main)."
  exit 0
fi
og diff --stat main "$tree"
[ -n "$DRY" ] && { echo "(dry run, nothing pushed)"; exit 0; }

new=$(GIT_AUTHOR_NAME="$(git config user.name)" GIT_AUTHOR_EMAIL="$(git config user.email)" \
      GIT_COMMITTER_NAME="$(git config user.name)" GIT_COMMITTER_EMAIL="$(git config user.email)" \
      og commit-tree "$tree" -p main -m "Sync from local copy $(date -u +%Y-%m-%dT%H:%M:%SZ)")
og push -q "$URL" "$new:refs/heads/main"
og update-ref refs/heads/main "$new"
og update-ref refs/heads/synced "$new"
echo "$DEST -> Overleaf $(og rev-parse --short "$new")"
