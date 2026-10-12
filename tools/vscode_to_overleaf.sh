#!/usr/bin/env bash
# One-way: local (vscode) -> GitHub -> Overleaf. No force, no merges.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! git diff --quiet HEAD -- latex; then
  echo "Commit your latex changes first." >&2
  exit 1
fi

# local -> GitHub
git push origin main

sync() { # prefix remote
  local prefix="$1" remote="$2" split tree base new
  split=$(git subtree split --prefix="$prefix" HEAD)
  tree=$(git rev-parse "$split^{tree}")

  # Overleaf's current tip
  git fetch "$remote" main
  base=$(git rev-parse FETCH_HEAD)

  # New commit: parent = Overleaf head, tree = our subtree
  new=$(git commit-tree "$tree" -p "$base" \
        -m "sync from local $(date -u +%Y-%m-%dT%H:%M:%SZ)")

  git push "$remote" "$new:main"
  echo "  $remote/main -> $new"
}

sync latex/SUIT_SEC@SAC overleaf-sac