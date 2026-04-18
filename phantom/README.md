# PHANTOM Protocol

> **Intern gebruik only · Zero Trust · Post-Quantum · 100% Rust**

Een intern, volledig privé communicatieplatform dat chat en mail in één systeem combineert. Geen centrale server. Geen telefoonnummer. Geen metadata-lekkage.

Dit is een **werk-in-uitvoering**: dit repo bevat op dit moment Sprint 1 van de planning uit het ontwerpdocument — identiteit en cryptografische fundamenten.

## Status

| Sprint | Doel | Status |
|---|---|---|
| 1 | Wallet-identiteit (BIP39 → 4 keypairs → fingerprint) | ✅ klaar |
| 2 | PQ-X3DH+ handshake en prekey-bundel | 🚧 |
| 3 | Hybride Double Ratchet met PQ-stap | 🚧 |
| 4 | Unified envelope sealing (chat ≡ mail) | 🚧 |
| 5 | P2P transport via libp2p + Kademlia DHT | 🚧 |
| 6 | Tauri desktop client | 🚧 |
| 7 | Audit logs, org-directory, compliance hooks | 🚧 |

## Architectuur (kort)

```
Mnemonic (24 BIP39-woorden)
    │  PBKDF2-HMAC-SHA512
Master seed (32 B)
    │  HKDF-SHA256 (domeinscheiding)
    ├── Ed25519     (sig klassiek)
    ├── X25519      (KEM klassiek)
    ├── ML-DSA-65   (sig PQ, FIPS 204)   [Sprint-1: OsRng-gegenereerd]
    ├── ML-KEM-1024 (KEM PQ, FIPS 203)   [Sprint-1: OsRng-gegenereerd]
    └── Storage key (32 B, lokale DB)

Fingerprint = BLAKE3(domain || alle pubs)[..8]
Weergave:   A1B2-C3D4-E5F6-G7H8
```

Het volledige ontwerp en de rationele staan in het projectdocument (intern).

## Bouwen en proberen

```bash
cd phantom
cargo build --release
cargo test

# Nieuwe identiteit
cargo run -q -p phantom-cli -- gen-identity

# Adres uit mnemonic halen
cargo run -q -p phantom-cli -- fingerprint \
    --mnemonic "abandon abandon abandon ... zone"
```

## Workspace

| Crate | Doel |
|---|---|
| `phantom-crypto` | Seed, identiteit, hybride PQ primitieven |
| `phantom-wire` | Envelope en size-buckets (skeleton) |
| `phantom-cli` | Ontwikkelaarshulpmiddelen |

## Cryptografische keuzes

- **Signatures**: Ed25519 + ML-DSA-65 (hybride)
- **KEM**: X25519 + ML-KEM-1024 (hybride)
- **Hashing**: BLAKE3
- **KDF**: HKDF-SHA256 met versioned info strings
- **Symmetrisch** (volgt in Sprint 2): ChaCha20-Poly1305

Waar mogelijk: audited upstream crates, geen eigen crypto.

## Wat PHANTOM **niet** doet

- ❌ Eigen onion-routing bovenop een klein netwerk van interne nodes.
  Voor externe anonimiteit: Tor via Arti als optionele transport-laag.
  Een zelfgebouwd 3-hop circuit op 50 mensen is zwakker, niet sterker.
- ❌ Telefoonnummer of e-mail als identifier.
- ❌ Centrale server. Geen Signal Foundation-achtig anker.
- ❌ Eigen cryptografische primitieven.

## Wallet-semantiek

Net als bij een cryptocurrency-wallet:

- **Je mnemonic is je identiteit.** Kwijt = weg. Geen recovery.
- **Je apparaat is vervangbaar.** Herstel = mnemonic invoeren op nieuw toestel.
- **Je geschiedenis is niet.** Lokale berichten staan versleuteld op één toestel tenzij je zelf een back-up maakt.

## Licentie

AGPL-3.0-only. De code van iedereen die PHANTOM draait mag geïnspecteerd worden.
