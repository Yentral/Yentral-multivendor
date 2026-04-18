//! # PHANTOM Protocol — cryptography
//!
//! Hybrid classical + post-quantum primitives:
//!
//! - Ed25519   + ML-DSA-65 (Dilithium3)  — signatures
//! - X25519    + ML-KEM-1024 (Kyber1024) — key encapsulation
//! - BLAKE3    — hashing / fingerprints
//! - HKDF-SHA256 — key derivation
//! - PBKDF2-HMAC-SHA512 (BIP39) — seed stretching
//!
//! All four keypairs and the local-storage key are deterministically derived
//! from a 32-byte master seed, which is derived from a 24-word BIP39
//! mnemonic. Lose the mnemonic → lose the identity. Like a crypto wallet.
//!
//! ## Sprint milestones
//!
//! - **2a**: seed-deterministic PQ keygen (done — stable fingerprint).
//! - **2b**: PQ-X3DH+ handshake (done — see [`handshake`]).
//! - **2c**: hybrid-signed PreKey bundle (done — see [`prekey`]).
//! - 3: Double Ratchet with periodic PQ re-keying.
//! - 4: Unified envelope sealing.

pub mod error;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod pqc;
pub mod prekey;
pub mod seed;

pub use error::CryptoError;
pub use handshake::{initiate, respond, InitialMessage, InitiatorOutput};
pub use identity::{Fingerprint, Identity, PublicIdentity};
pub use prekey::{
    BundleBody, HybridSignature, IdentityPubs, OneTimePreKeyPub, OneTimePreKeySecret, PreKeyBundle,
    PublishedBundle, SignedPreKeyPub, SignedPreKeySecret, PHANTOM_PROTOCOL_VERSION,
};
pub use seed::Seed;
