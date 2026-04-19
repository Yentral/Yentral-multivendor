#!/usr/bin/env bash
# Extract phantom/ into a standalone new git repository.
#
# Usage (path A — preserve history):
#   ./scripts/extract-to-new-repo.sh git@github.com:you/phantom-chat.git
#
# Usage (path B — flat, no history):
#   ./scripts/extract-to-new-repo.sh --flat git@github.com:you/phantom-chat.git
#
# Prerequisites: you've created an EMPTY private repo on github.com with that URL.

set -euo pipefail

MODE="preserve"
if [[ "${1:-}" == "--flat" ]]; then
  MODE="flat"
  shift
fi

REMOTE="${1:-}"
if [[ -z "$REMOTE" ]]; then
  echo "usage: $0 [--flat] <git-remote-url>"
  echo "e.g.   $0 git@github.com:yourname/phantom-chat.git"
  exit 1
fi

# Work from the repo root (parent of phantom/)
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"
echo "▶ Source repo root: $ROOT"

WORK=$(mktemp -d)
echo "▶ Scratch dir:      $WORK"

case "$MODE" in
  preserve)
    echo "▶ Mode: preserve commit history for phantom/ subtree"
    # Create a branch containing only the phantom/ subtree with its history.
    git subtree split --prefix=phantom -b phantom-extracted
    git clone --single-branch --branch phantom-extracted "$ROOT" "$WORK/newrepo"
    cd "$WORK/newrepo"
    # Collapse the default "main" branch and rename our extracted branch to it.
    git branch -m phantom-extracted main
    git remote set-url origin "$REMOTE"
    ;;
  flat)
    echo "▶ Mode: flat, single initial commit"
    mkdir -p "$WORK/newrepo"
    # Copy everything from phantom/ EXCEPT target/ and build noise.
    (cd phantom && \
      find . -type f \
        ! -path '*/target/*' \
        ! -path '*/desktop/target/*' \
        ! -path '*/desktop/gen/*' \
        ! -name '.DS_Store' \
        -print0 | \
      tar --null --files-from=- -cf - ) | \
      tar -xf - -C "$WORK/newrepo"
    cd "$WORK/newrepo"
    git init -b main
    git add .
    git commit -m "Initial import of PHANTOM Protocol

Extracted from Yentral-multivendor@$(cd "$ROOT" && git rev-parse --short HEAD).
79 tests passing, all seven sprints complete.
See README.md for architecture overview and MAC_GETTING_STARTED.md
for installation instructions."
    git remote add origin "$REMOTE"
    ;;
esac

echo ""
echo "▶ New local repo ready at:   $WORK/newrepo"
echo "▶ Remote:                     $REMOTE"
echo ""
echo "▶ To push:"
echo "    cd $WORK/newrepo"
echo "    git push -u origin main"
echo ""
echo "▶ Verify first:"
echo "    cd $WORK/newrepo"
echo "    git log --oneline | head"
echo "    ls"
