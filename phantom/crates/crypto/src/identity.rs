//! PHANTOM identity — the four hybrid keypairs that define a user.
//!
//! ```text
//!               Mnemonic (24 words)
//!                       │
//!                PBKDF2-HMAC-SHA512
//!                       │
//!               Master seed (32 B)
//!                       │
//!       ┌───────────────┼───────────────┬───────────────┐
//!       │               │               │               │
//!   HKDF "ed25519"  HKDF "x25519"  HKDF "mldsa"   HKDF "mlkem"   HKDF "storage"
//!       │               │               │               │               │
//!   Ed25519         X25519         ML-DSA-65      ML-KEM-1024      32-B AES key
//!   (sign)          (KEM)          (sign, PQ)     (KEM, PQ)        (local DB)
//! ```
//!
//! All four keypairs are deterministically derived from the master seed via
//! HKDF-SHA256 with protocol-scoped info strings. Given the same mnemonic,
//! you always reconstruct the exact same identity — including PQ keys.
//!
//! The fingerprint is BLAKE3(domain || all_pubkeys) truncated to 8 bytes and
//! displayed as `A1B2-C3D4-E5F6-G7H8`. It IS the user's address — no email,
//! no phone, no @ symbol.

use ed25519_dalek::{SigningKey as Ed25519Sk, VerifyingKey as Ed25519Pk};
use x25519_dalek::{PublicKey as X25519Pk, StaticSecret as X25519Sk};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::kdf::{self, info};
use crate::pqc::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlKem, MlKemPublicKey, MlKemSecretKey};
use crate::seed::Seed;

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// An 8-byte fingerprint over all four public keys. Rendered as
/// `A1B2-C3D4-E5F6-G7H8` (16 hex chars + 3 dashes = 19 chars).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 8]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Format as `A1B2-C3D4-E5F6-G7H8` (upper-case hex, dash every 2 bytes).
    pub fn display(&self) -> String {
        let hex = hex::encode_upper(self.0);
        format!("{}-{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
    }

    /// Parse `A1B2-C3D4-E5F6-G7H8` (dashes optional, case-insensitive).
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let cleaned: String = s.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect();
        if cleaned.len() != 16 {
            return Err(CryptoError::InvalidFingerprint);
        }
        let bytes = hex::decode(&cleaned).map_err(|_| CryptoError::InvalidFingerprint)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(Fingerprint(out))
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.display())
    }
}

impl core::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fingerprint({})", self.display())
    }
}

// ---------------------------------------------------------------------------
// Public identity
// ---------------------------------------------------------------------------

/// The portion of an identity that is safe to publish: four public keys.
#[derive(Clone)]
pub struct PublicIdentity {
    pub ed25519:   Ed25519Pk,
    pub x25519:    X25519Pk,
    pub mldsa65:   MlDsaPublicKey,
    pub mlkem1024: MlKemPublicKey,
}

impl PublicIdentity {
    /// Canonical byte representation used when fingerprinting or signing a
    /// bundle. Order MUST match the sizes in `PublicIdentity::fingerprint`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            32 + 32 + self.mldsa65.as_bytes().len() + self.mlkem1024.as_bytes().len(),
        );
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(self.mldsa65.as_bytes());
        out.extend_from_slice(self.mlkem1024.as_bytes());
        out
    }

    /// BLAKE3 fingerprint over all four public keys, truncated to 8 bytes.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(info::FINGERPRINT);
        hasher.update(&self.to_canonical_bytes());
        let mut out = [0u8; 8];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        Fingerprint(out)
    }
}

// ---------------------------------------------------------------------------
// Full identity (private material)
// ---------------------------------------------------------------------------

/// The user's full identity: four keypairs plus a local-storage key.
///
/// Constructed via `Identity::from_seed`. Secret material is zeroed on drop.
pub struct Identity {
    pub ed25519_sk:   Ed25519Sk,
    pub ed25519_pk:   Ed25519Pk,
    pub x25519_sk:    X25519Sk,
    pub x25519_pk:    X25519Pk,
    pub mldsa65_sk:   MlDsaSecretKey,
    pub mldsa65_pk:   MlDsaPublicKey,
    pub mlkem1024_sk: MlKemSecretKey,
    pub mlkem1024_pk: MlKemPublicKey,
    pub storage_key:  StorageKey,
}

/// 32-byte symmetric key for encrypting the local database.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StorageKey(pub [u8; 32]);

impl Identity {
    /// Derive a complete identity from the master seed.
    ///
    /// All four keypairs are deterministic: the same seed always yields the
    /// same identity. Post-quantum keygen uses ChaCha20Rng seeded with an
    /// HKDF-derived sub-seed, so the ML-DSA-65 and ML-KEM-1024 keypairs are
    /// fully reproducible from the mnemonic alone.
    pub fn from_seed(seed: &Seed) -> Result<Self, CryptoError> {
        // Classical: deterministic from seed.
        let ed25519_seed: [u8; 32] = kdf::hkdf_expand(seed.as_bytes(), info::ED25519_SIGN)?;
        let ed25519_sk = Ed25519Sk::from_bytes(&ed25519_seed);
        let ed25519_pk = ed25519_sk.verifying_key();

        let x25519_seed: [u8; 32] = kdf::hkdf_expand(seed.as_bytes(), info::X25519_KEM)?;
        let x25519_sk = X25519Sk::from(x25519_seed);
        let x25519_pk = X25519Pk::from(&x25519_sk);

        // Post-quantum: deterministic from seed via ChaCha20Rng sub-seeds.
        let mldsa_seed: [u8; 32] = kdf::hkdf_expand(seed.as_bytes(), info::MLDSA65_SIGN)?;
        let (mldsa65_pk, mldsa65_sk) = MlDsa::keypair_from_seed(&mldsa_seed);

        let mlkem_seed: [u8; 32] = kdf::hkdf_expand(seed.as_bytes(), info::MLKEM1024_KEM)?;
        let (mlkem1024_pk, mlkem1024_sk) = MlKem::keypair_from_seed(&mlkem_seed);

        let storage_bytes: [u8; 32] = kdf::hkdf_expand(seed.as_bytes(), info::STORAGE)?;
        let storage_key = StorageKey(storage_bytes);

        Ok(Identity {
            ed25519_sk,
            ed25519_pk,
            x25519_sk,
            x25519_pk,
            mldsa65_sk,
            mldsa65_pk,
            mlkem1024_sk,
            mlkem1024_pk,
            storage_key,
        })
    }

    /// Extract just the public portion of the identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            ed25519:   self.ed25519_pk,
            x25519:    self.x25519_pk,
            mldsa65:   self.mldsa65_pk.clone(),
            mlkem1024: self.mlkem1024_pk.clone(),
        }
    }

    /// Convenience: compute the fingerprint of this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public().fingerprint()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_keys_are_deterministic() {
        let (seed, mnemonic) = Seed::generate();
        let id_a = Identity::from_seed(&seed).unwrap();

        let reseeded = Seed::from_mnemonic(&mnemonic, "");
        let id_b = Identity::from_seed(&reseeded).unwrap();

        // Classical
        assert_eq!(id_a.ed25519_pk.as_bytes(), id_b.ed25519_pk.as_bytes());
        assert_eq!(id_a.x25519_pk.as_bytes(), id_b.x25519_pk.as_bytes());
        assert_eq!(id_a.storage_key.0, id_b.storage_key.0);

        // Post-quantum — the whole point of Sprint 2a.
        assert_eq!(id_a.mldsa65_pk.as_bytes(), id_b.mldsa65_pk.as_bytes());
        assert_eq!(id_a.mlkem1024_pk.as_bytes(), id_b.mlkem1024_pk.as_bytes());

        // Fingerprint must now be stable too.
        assert_eq!(id_a.fingerprint(), id_b.fingerprint());
    }

    #[test]
    fn fingerprint_format_is_a1b2_c3d4_e5f6_g7h8() {
        let (seed, _) = Seed::generate();
        let id = Identity::from_seed(&seed).unwrap();
        let fp = id.fingerprint().display();

        // 19 chars: 16 hex + 3 dashes
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.as_bytes()[4], b'-');
        assert_eq!(fp.as_bytes()[9], b'-');
        assert_eq!(fp.as_bytes()[14], b'-');
    }

    #[test]
    fn fingerprint_parse_roundtrip() {
        let (seed, _) = Seed::generate();
        let id = Identity::from_seed(&seed).unwrap();
        let fp = id.fingerprint();
        let parsed = Fingerprint::parse(&fp.display()).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn fingerprint_parse_ignores_dashes_and_case() {
        let canonical = "A1B2-C3D4-E5F6-0708";
        let variants = [
            "A1B2-C3D4-E5F6-0708",
            "a1b2-c3d4-e5f6-0708",
            "a1b2c3d4e5f60708",
            "A1B2C3D4E5F60708",
        ];
        let expected = Fingerprint::parse(canonical).unwrap();
        for v in variants {
            assert_eq!(Fingerprint::parse(v).unwrap(), expected);
        }
    }

    #[test]
    fn different_seeds_yield_different_fingerprints() {
        let (seed_a, _) = Seed::generate();
        let (seed_b, _) = Seed::generate();
        let fp_a = Identity::from_seed(&seed_a).unwrap().fingerprint();
        let fp_b = Identity::from_seed(&seed_b).unwrap().fingerprint();
        assert_ne!(fp_a, fp_b);
    }
}
