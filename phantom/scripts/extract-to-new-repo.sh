#!/usr/bin/env bash
# Extract phantom/ into a standalone new git repository, and ship it with
# a working .github/workflows/build-mac.yml so Apple-hosted Mac builds
# work on the first push.
#
# Usage (preserve history — recommended):
#   ./scripts/extract-to-new-repo.sh https://github.com/you/phantom-chat.git
#
# Usage (flat — single initial commit):
#   ./scripts/extract-to-new-repo.sh --flat https://github.com/you/phantom-chat.git
#
# Prerequisites: you've created an EMPTY private repo on github.com with
# that URL. Do NOT initialize it with a README or .gitignore.

set -euo pipefail

MODE="preserve"
if [[ "${1:-}" == "--flat" ]]; then
  MODE="flat"
  shift
fi

REMOTE="${1:-}"
if [[ -z "$REMOTE" ]]; then
  cat <<EOF
usage: $0 [--flat] <git-remote-url>

Examples:
  $0 https://github.com/bleuproton/phantom-chat.git
  $0 --flat https://github.com/bleuproton/phantom-chat.git
  $0 git@github.com:bleuproton/phantom-chat.git
EOF
  exit 1
fi

# Work from the repo root (parent of phantom/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."
ROOT="$(pwd)"
echo "▶ Source repo root: $ROOT"

WORK=$(mktemp -d)
echo "▶ Scratch dir:      $WORK"

case "$MODE" in
  preserve)
    echo "▶ Mode: preserve commit history for phantom/ subtree"
    git subtree split --prefix=phantom -b phantom-extracted
    git clone --single-branch --branch phantom-extracted "$ROOT" "$WORK/newrepo"
    cd "$WORK/newrepo"
    git branch -m phantom-extracted main
    git remote set-url origin "$REMOTE"
    ;;
  flat)
    echo "▶ Mode: flat, single initial commit"
    mkdir -p "$WORK/newrepo"
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

# ---------------------------------------------------------------------------
# Add the adapted GitHub Actions workflow (paths without phantom/ prefix).
# ---------------------------------------------------------------------------
echo "▶ Installing .github/workflows/build-mac.yml (Mac Actions build)"
mkdir -p .github/workflows
cp "$SCRIPT_DIR/build-mac.yml.template" .github/workflows/build-mac.yml

# Also drop a CI workflow that runs tests on every push (Linux, much cheaper).
cat > .github/workflows/ci.yml <<'CIEOF'
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: '1.95.0'
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --workspace -- -D warnings
      - run: cargo test --workspace
CIEOF

git add .github/
git commit -m "ci: Mac .dmg build workflow + Linux test matrix"

# ---------------------------------------------------------------------------
# Print next steps
# ---------------------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "▶ New local repo ready at:    $WORK/newrepo"
echo "▶ Remote:                      $REMOTE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "▶ Quick verify:"
echo "    cd $WORK/newrepo"
echo "    git log --oneline | head"
echo "    ls"
echo ""
echo "▶ Push (use HTTPS + PAT, or SSH if you set up keys):"
echo "    cd $WORK/newrepo"
echo "    git push -u origin main"
echo ""
echo "▶ After push:"
echo "    - github.com/$REMOTE → Actions tab"
echo "    - 'build — macOS' workflow → Run workflow → Run workflow"
echo "    - Wait 15 min → scroll to Artifacts → download phantom-apple-silicon-dmg"
echo ""
