//! # PHANTOM Protocol — cryptography
//!
//! Hybrid classical + post-quantum primitives:
//!
//! - Ed25519   + ML-DSA-65 (Dilithium3)  — signatures
//! - X25519    + ML-KEM-1024 (Kyber1024) — key encapsulation
//! - BLAKE3    — hashing / fingerprints
//! - HKDF-SHA256 — key derivation
//! - Argon2id  — seed stretching (BIP39 passphrase)
//!
//! Identity is derived deterministically from a 32-byte master seed,
//! which is itself derived from a BIP39 mnemonic (24 words).
//!
//! Lose the seed → lose the identity. Like a crypto wallet.

pub mod error;
pub mod kdf;
pub mod seed;
pub mod identity;
pub mod pqc;

pub use error::CryptoError;
pub use identity::{Fingerprint, Identity, PublicIdentity};
pub use seed::Seed;
