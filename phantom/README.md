# PHANTOM Protocol

> **Intern gebruik only · Zero Trust · Post-Quantum · 100% Rust**

Een intern, volledig privé communicatieplatform dat chat en mail in één systeem combineert. Geen centrale server. Geen telefoonnummer. Geen metadata-lekkage.

## Status — alle sprints af

| Sprint | Doel | Status |
|---|---|---|
| 1  | Wallet-identiteit (BIP39 → 4 keypairs → fingerprint) | ✅ |
| 2a | Deterministische PQ keygen, stabiele fingerprint | ✅ |
| 2b | PQ-X3DH+ hybride handshake | ✅ |
| 2c | Gesigneerde PreKey bundle (Ed25519 + ML-DSA-65) | ✅ |
| 3  | Double Ratchet met ChaCha20-Poly1305 | ✅ |
| 4  | Unified envelope (chat ≡ mail ≡ file), size-buckets, chunking | ✅ |
| 5  | P2P transport: libp2p + Kademlia DHT + store-forward | ✅ |
| 6  | Desktop client: REPL + Tauri-skeleton | ✅ |
| 7  | Audit log + org-directory (ISO/SOC hooks) | ✅ |

## Workspace

```
phantom/
├── Cargo.toml                workspace
├── rust-toolchain.toml       rustc 1.95.0
├── crates/
│   ├── crypto/               identity, PQ, handshake, ratchet, aead
│   ├── wire/                 envelope type + size buckets
│   ├── protocol/             unified sealing (chat/mail/file)
│   ├── p2p/                  libp2p Swarm, DHT, store-forward
│   ├── audit/                encrypted append-only log
│   ├── directory/            signed org roster
│   ├── chat/                 REPL client + ChatApp core
│   └── cli/                  dev tool (demo-handshake, demo-session, …)
└── desktop/                  Tauri 2 GUI shell (excluded from workspace)
```

## Bouwen & proberen

```bash
cd phantom
cargo build --release
cargo test                     # 79 tests, alle green

# Dev tool
cargo run -q -p phantom-cli -- gen-identity
cargo run -q -p phantom-cli -- demo-handshake
cargo run -q -p phantom-cli -- demo-session
cargo run -q -p phantom-cli -- demo-mail

# Interactieve chat client
cargo run -p phantom-chat --bin phantom-chat
```

## De stack, van onder naar boven

```
┌─────────────────────────────────────────────────────────┐
│  phantom-chat  (REPL)    ·    desktop/  (Tauri GUI)     │
├─────────────────────────────────────────────────────────┤
│  phantom-p2p   libp2p + Kademlia + store-and-forward    │
├─────────────────────────────────────────────────────────┤
│  phantom-protocol   unified envelope sealing (chunks,   │
│                     size buckets, chat ≡ mail ≡ file)   │
├─────────────────────────────────────────────────────────┤
│  phantom-crypto  ratchet · PQ-X3DH+ · ChaCha20-Poly1305 │
│                  identity · Kyber1024 · Dilithium3       │
├─────────────────────────────────────────────────────────┤
│  phantom-wire    envelope type · size buckets            │
├─────────────────────────────────────────────────────────┤
│  phantom-audit   hash-chained encrypted log              │
│  phantom-directory   signed org roster (TOFU-CA)         │
└─────────────────────────────────────────────────────────┘
```

## Cryptografische keuzes

- **Wallet**: BIP39 24-woorden → PBKDF2-HMAC-SHA512 → 32 B seed
- **Signatures** (hybride): Ed25519 + ML-DSA-65 (FIPS 204)
- **KEM** (hybride): X25519 + ML-KEM-1024 (FIPS 203)
- **Symmetric AEAD**: ChaCha20-Poly1305 (RFC 8439)
- **Hashing**: BLAKE3
- **KDF**: HKDF-SHA256 met versioned domain tags
- Geen eigen crypto. Pure-Rust crates: RustCrypto + dalek + hashes.

## Wat PHANTOM **niet** doet

- ❌ Eigen onion routing op een klein intern netwerk. Gebruik Tor via Arti als transport-laag voor externe anonimiteit.
- ❌ Telefoonnummer of e-mail als identifier. Fingerprint = adres.
- ❌ Centrale server. Geen Signal-Foundation-achtig anker.
- ❌ PQ ratchet op elk bericht (zou 30× bandbreedte kosten). PQ zit in initial handshake + periodieke re-key.

## Wallet-semantiek

- **Je mnemonic is je identiteit.** Kwijt = weg. Geen recovery.
- **Volledig deterministisch** — classical én PQ keys uit dezelfde 24 woorden.
- **Apparaat vervangbaar.** Nieuw toestel + mnemonic = zelfde fingerprint.
- **Geschiedenis niet.** Lokale berichten staan versleuteld tenzij je zelf back-upt.

## Licentie

AGPL-3.0-only.
