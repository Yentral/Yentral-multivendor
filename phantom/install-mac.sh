#!/usr/bin/env bash
# PHANTOM Protocol — one-command installer for macOS (Apple Silicon & Intel).
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/Yentral/Yentral-multivendor/claude/phantom-protocol-UUWEf/phantom/install-mac.sh | bash
#
# Or locally after cloning:
#   ./install-mac.sh [--gui|--repl|--test]
#
# What it does:
#   1. Checks Xcode Command Line Tools (prompts install if missing)
#   2. Installs Rust via rustup if not present
#   3. Installs `tauri-cli` if GUI is requested
#   4. Builds and launches the chosen client

set -euo pipefail

MODE="${1:-gui}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_red()   { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_blue()  { printf '\033[36m%s\033[0m\n' "$*"; }
c_dim()   { printf '\033[90m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 0. Sanity checks
# ---------------------------------------------------------------------------
if [[ "$(uname)" != "Darwin" ]]; then
  c_red "Dit script is voor macOS. Voor Linux: zie README.md."
  exit 1
fi

ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
  c_blue "▶ Apple Silicon (M1/M2/M3/M4) gedetecteerd"
else
  c_blue "▶ Intel Mac gedetecteerd — werkt ook, maar traag op libp2p-build"
fi

# ---------------------------------------------------------------------------
# 1. Xcode Command Line Tools
# ---------------------------------------------------------------------------
if ! xcode-select -p >/dev/null 2>&1; then
  c_red "▶ Xcode Command Line Tools ontbreken. Start installer..."
  xcode-select --install
  c_dim "  Wacht tot installer klaar is en draai dit script opnieuw."
  exit 1
else
  c_green "✓ Xcode Command Line Tools aanwezig"
fi

# ---------------------------------------------------------------------------
# 2. Rust toolchain
# ---------------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  c_blue "▶ Rust installeren via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
  source "$HOME/.cargo/env"
fi
source "$HOME/.cargo/env" 2>/dev/null || true
c_green "✓ cargo: $(cargo --version)"

# ---------------------------------------------------------------------------
# 3. Into the workspace
# ---------------------------------------------------------------------------
if [[ -f "$REPO_DIR/Cargo.toml" && -d "$REPO_DIR/crates" ]]; then
  WORK_DIR="$REPO_DIR"
else
  c_red "▶ Kon phantom-workspace niet vinden op $REPO_DIR"
  c_red "  Zorg dat je dit script draait vanuit de phantom/ directory."
  exit 1
fi
cd "$WORK_DIR"
c_green "✓ Workspace: $WORK_DIR"

# ---------------------------------------------------------------------------
# 4. Run the selected mode
# ---------------------------------------------------------------------------
case "$MODE" in
  --test|test)
    c_blue "▶ cargo test (eerste keer: ~5 min op M1, ~15 min op Intel)"
    cargo test --release
    c_green "✓ Alle tests groen"
    ;;

  --repl|repl)
    c_blue "▶ Terminal-client starten (eerste keer: ~5 min build)"
    c_dim "  Commando's na start: /help  /id  /listen  /dial  /contact  /send  /audit  /quit"
    cargo run --release -p phantom-chat --bin phantom-chat
    ;;

  --gui|gui|"")
    if ! command -v cargo-tauri >/dev/null 2>&1; then
      c_blue "▶ tauri-cli installeren (eenmalig, ~2 min)"
      cargo install tauri-cli --version '^2'
    fi
    c_green "✓ tauri-cli: $(cargo-tauri --version)"

    cd "$WORK_DIR/desktop"
    c_blue "▶ GUI starten — eerste build duurt 10-15 min op M1"
    c_blue "  (libp2p + ml-kem + ml-dsa + webkit2 bindings compileren)"
    cargo tauri dev
    ;;

  --bundle|bundle)
    if ! command -v cargo-tauri >/dev/null 2>&1; then
      c_blue "▶ tauri-cli installeren"
      cargo install tauri-cli --version '^2'
    fi
    cd "$WORK_DIR/desktop"
    c_blue "▶ Bouwen van distributeerbare .app + .dmg..."
    cargo tauri build
    c_green "✓ Output: $WORK_DIR/desktop/target/release/bundle/"
    ls -la target/release/bundle/ 2>/dev/null || true
    ;;

  *)
    c_red "Onbekende modus: $MODE"
    cat <<EOF

Gebruik:
  ./install-mac.sh              # GUI (standaard, opent venster)
  ./install-mac.sh --repl       # Terminal-client
  ./install-mac.sh --test       # Alleen alle tests draaien
  ./install-mac.sh --bundle     # .app + .dmg voor distributie bouwen

EOF
    exit 1
    ;;
esac
