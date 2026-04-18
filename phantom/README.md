# PHANTOM Protocol

> **Intern gebruik only · Zero Trust · Post-Quantum · 100% Rust**

Een intern, volledig privé communicatieplatform dat chat en mail in één systeem combineert. Geen centrale server. Geen telefoonnummer. Geen metadata-lekkage.

## Status

| Sprint | Doel | Status |
|---|---|---|
| 1 | Wallet-identiteit (BIP39 → 4 keypairs → fingerprint) | ✅ klaar |
| 2a | Deterministische PQ keygen, stabiele fingerprint | ✅ klaar |
| 2b | PQ-X3DH+ hybride handshake (initiator + responder) | ✅ klaar |
| 2c | Gesigneerde PreKey bundle (Ed25519 + ML-DSA-65) | ✅ klaar |
| 3  | Double Ratchet met ChaCha20-Poly1305 sealing | ✅ klaar |
| 4  | Unified envelope (chat ≡ mail) + size buckets | 🚧 |
| 5  | P2P transport via libp2p + Kademlia DHT | 🚧 |
| 6  | Tauri desktop client | 🚧 |
| 7  | Audit logs, org-directory, compliance hooks | 🚧 |

## Architectuur

```
Mnemonic (24 BIP39-woorden)
    │  PBKDF2-HMAC-SHA512
Master seed (32 B)
    │  HKDF-SHA256 (domeinscheiding)
    ├── Ed25519     (sig klassiek, 32 B pub)
    ├── X25519      (KEM klassiek, 32 B pub)
    ├── ML-DSA-65   (sig PQ, FIPS 204, 1952 B pub)    ← deterministisch sinds 2a
    ├── ML-KEM-1024 (KEM PQ, FIPS 203, 1568 B pub)    ← deterministisch sinds 2a
    └── Storage key (32 B, lokale DB)

Fingerprint = BLAKE3(domain || alle pubs)[..8]
Weergave:   A1B2-C3D4-E5F6-G7H8
```

### PQ-X3DH+ handshake (Sprint 2b)

```
Alice                                 Wire                    Bob
─────                                ──────                  ─────
fetch bundle ─────────────────────────────────────────►  publishes bundle

4× X25519 DH:
  IK_A × SPK_B
  EK   × IK_B
  EK   × SPK_B
  EK   × OTPK_B
+ 2× ML-KEM-1024 encap (SPK, OTPK)
→ HKDF-SHA256 → SK (32 B)

InitialMessage ───────────────────────────────────────►  mirror DH + decap
                                                         → HKDF-SHA256 → SK

                           SK matches ✓
```

Een aanvaller moet **beide** X25519 én ML-KEM-1024 breken om `SK` te kennen. Dekt de *Harvest Now, Decrypt Later* dreiging.

### PreKey bundle (Sprint 2c)

Elke bundle wordt met **twee** handtekeningen gebonden:

- Ed25519 (64 B) — klassiek bewezen
- ML-DSA-65 (3309 B) — post-quantum (FIPS 204)

Verifier controleert beide. Hybride security: beide moeten gebroken worden voordat een bundel gevalideerd kan worden.

## Bouwen en proberen

```bash
cd phantom
cargo build --release
cargo test          # 34 tests, alle green

# Nieuwe identiteit (wallet-stijl)
cargo run -q -p phantom-cli -- gen-identity

# Adres uit mnemonic
cargo run -q -p phantom-cli -- fingerprint \
    --mnemonic "abandon abandon ... art"

# Live demo van de PQ-X3DH+ handshake
cargo run -q -p phantom-cli -- demo-handshake

# Live demo van een volledig gesprek (handshake + ratchet + messages)
cargo run -q -p phantom-cli -- demo-session
```

Demo-output:

```
▶ Genereer twee verse identiteiten (Alice + Bob)...
  Alice: 1FA6-FE31-E916-E91B
  Bob:   E7E6-2207-9B5A-339A

▶ Bob publiceert een verse signed PreKey bundle...
  Bundle gesigneerd met Ed25519 (64 B) + ML-DSA-65 (3309 B)
  Hybride signature geverifieerd ✓

▶ Alice haalt de bundle op en start een PQ-X3DH+ handshake...
  4× X25519 DH + 2× ML-KEM encapsulation → HKDF-SHA256
  Alice's root key:  1edc5e2e5b254aad31a042c83970323a

▶ Bob ontvangt InitialMessage en reconstrueert de sleutel...
  Bob's root key:    1edc5e2e5b254aad31a042c83970323a

✓ Beide zijden hebben dezelfde 32-byte root key afgeleid.
```

## Workspace

| Crate | Doel |
|---|---|
| `phantom-crypto` | Seed, identiteit, PQ primitieven, PreKey bundle, PQ-X3DH+, Double Ratchet, AEAD |
| `phantom-wire` | Envelope + size buckets (skeleton voor unified chat≡mail in Sprint 4) |
| `phantom-cli` | Ontwikkelaarshulpmiddelen + `demo-handshake` + `demo-session` |

## Cryptografische keuzes

- **Signatures**: Ed25519 + ML-DSA-65 (hybride)
- **KEM**: X25519 + ML-KEM-1024 (hybride)
- **Hashing**: BLAKE3
- **KDF**: HKDF-SHA256 met versioned info strings
- **Symmetrisch** (Sprint 4): ChaCha20-Poly1305
- Geen eigen crypto. Pure-Rust RustCrypto + dalek implementaties.

## Wallet-semantiek

- **Je mnemonic is je identiteit.** Kwijt = weg. Geen recovery.
- **Volledig deterministisch** — classical én PQ keys komen uit dezelfde 24 woorden.
- **Je apparaat is vervangbaar.** Nieuw toestel + mnemonic = zelfde fingerprint.
- **Je geschiedenis niet.** Lokale berichten staan versleuteld op één toestel tenzij je zelf een back-up maakt.

## Licentie

AGPL-3.0-only. De code van iedereen die PHANTOM draait mag geïnspecteerd worden.
