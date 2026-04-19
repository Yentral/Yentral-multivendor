# PHANTOM op Mac M1 — drie paden

Je hoeft niets te compileren als je geen zin hebt. De GitHub Actions-workflow (`.github/workflows/phantom-mac-build.yml`) bouwt automatisch een `.dmg` op Apple-hardware.

## 🟢 Pad 1 — `.dmg` downloaden (makkelijkst, geen tools nodig)

1. Ga naar de repo op GitHub → **Actions** tab
2. Klik op de workflow **"phantom — mac build"**
3. Klik op de laatste geslaagde run → scroll naar **Artifacts**
4. Download `phantom-desktop-apple-silicon-dmg`
5. Pak uit → dubbelklik de `.dmg` → sleep PHANTOM naar `/Applications`
6. Eerste start: Gatekeeper zeurt (niet genotariseerd). Rechtsklik → **Open** → **Open** bevestigen

**Workflow handmatig triggeren** als er nog geen recente run is:
1. Actions tab → "phantom — mac build" → **Run workflow** → branch kiezen → **Run**
2. Wacht ~15 min (eerste build), daarna artifact ophalen

## 🟡 Pad 2 — Lokaal builden (GUI + dev-mode)

Clone en draai het install-script:

```bash
git clone https://github.com/Yentral/Yentral-multivendor.git
cd Yentral-multivendor
git checkout claude/phantom-protocol-UUWEf
cd phantom
./install-mac.sh              # start GUI (eerste keer 10-15 min build)
```

Andere modi:
```bash
./install-mac.sh --repl       # terminal-client
./install-mac.sh --test       # alle 79 tests draaien
./install-mac.sh --bundle     # .app + .dmg bouwen in target/release/bundle/
```

## 🔵 Pad 3 — Handmatig (als je precies wilt weten wat er gebeurt)

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Tauri CLI
cargo install tauri-cli --version '^2'

# Clone
git clone https://github.com/Yentral/Yentral-multivendor.git
cd Yentral-multivendor/phantom
git checkout claude/phantom-protocol-UUWEf

# Dev-mode (hot reload)
cd desktop
cargo tauri dev

# Of: distributie-bundle
cargo tauri build
# Output: target/release/bundle/macos/PHANTOM.app
#         target/release/bundle/dmg/PHANTOM_0.1.0_aarch64.dmg
```

## Verwachte buildtijden op M1

| Stap | Tijd |
|---|---|
| Rust installatie | 2 min |
| `cargo install tauri-cli` | 2-3 min |
| Eerste `cargo tauri build` | 10-15 min |
| Incrementele rebuild | 5-30 sec |
| `cargo test --release` | 5 min |

## Als iets stuk is

| Symptoom | Fix |
|---|---|
| `linker 'cc' not found` | `xcode-select --install` |
| Gatekeeper blokkeert `.app` | Rechtsklik → Open → Open |
| `dyld: Library not loaded` | `brew install libsoup libiconv` |
| GUI opent maar is wit | Rechtsklik in het venster → Inspect Element → Console |

## Niet vergeten

Eerste start genereert een **mnemonic van 24 woorden**. Schrijf die op. Anders verlies je je identiteit bij een herstart. Dit is bewust — wallet-semantiek, zoals in het design document.
