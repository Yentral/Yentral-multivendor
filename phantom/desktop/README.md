# PHANTOM Desktop (Tauri 2)

Thin GUI wrapper around the `phantom-chat` core. This directory is
**deliberately outside the workspace** — building Tauri on Linux needs
native packages (`webkit2gtk-4.1`, `libsoup-3.0`, `librsvg2`) that may not
be installed on every build machine.

## Build prerequisites

### Linux (Debian/Ubuntu)
```
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev \
                 librsvg2-dev libayatana-appindicator3-dev \
                 build-essential curl wget file
```

### macOS
Xcode command-line tools are enough.

### Windows
Install WebView2 runtime (usually bundled with Edge). Then Visual Studio
Build Tools for the MSVC toolchain.

## Run

```
cd phantom/desktop
cargo install tauri-cli --version ^2
cargo tauri dev
```

The frontend lives in `dist/` — a single `index.html` with vanilla JS that
calls Tauri commands over IPC.

## Commands exposed to the webview

| IPC command | What it does |
|-------------|--------------|
| `bootstrap` | Generate fresh identity + return `{fingerprint, peer_id, mnemonic}` |
| `recover` | Recover identity from a 24-word mnemonic |
| `listen_on` | Start a libp2p listener on a given multiaddr |
| `dial` | Dial a peer by multiaddr |
| `send_chat` | Send a chat to a fingerprint |

## Relation to the workspace

The binary links against `phantom-chat`, `phantom-crypto`, and
`phantom-protocol` via relative paths. All business logic is shared with
the terminal-based REPL in `crates/chat/src/main.rs` — this shell is only
UI.
