//! Master seed — the single source of identity.
//!
//! The seed is a 32-byte high-entropy value. In normal use it is derived from
//! a 24-word BIP39 mnemonic (256 bits of entropy) via PBKDF2-HMAC-SHA512,
//! then truncated to 32 bytes. The mnemonic is what the user writes down.
//!
//! Losing the mnemonic = losing the identity. There is no recovery.

use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

pub const SEED_LEN: usize = 32;

/// The 32-byte master seed. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed(pub [u8; SEED_LEN]);

impl Seed {
    /// Generate a fresh seed using the OS CSPRNG and return (seed, mnemonic).
    ///
    /// The caller MUST display the mnemonic to the user and prompt them to
    /// write it down. Without the mnemonic, the seed cannot be recovered.
    pub fn generate() -> (Self, Mnemonic) {
        // 32 bytes of entropy → 24-word mnemonic
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("32-byte entropy is always valid for BIP39");

        let seed = Self::from_mnemonic(&mnemonic, "");
        entropy.zeroize();
        (seed, mnemonic)
    }

    /// Re-derive the seed from a previously generated mnemonic.
    ///
    /// The passphrase is optional; empty string reproduces the default
    /// derivation. A non-empty passphrase creates an *entirely different*
    /// identity from the same mnemonic — a so-called "25th word".
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        // BIP39 to_seed produces 64 bytes via PBKDF2-HMAC-SHA512, 2048 rounds.
        let full = mnemonic.to_seed(passphrase);
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&full[..SEED_LEN]);
        Seed(seed)
    }

    /// Parse a mnemonic phrase (space-separated words) in English.
    pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, CryptoError> {
        Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))
    }

    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Seed([REDACTED; {}])", SEED_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_roundtrip() {
        let (seed, mnemonic) = Seed::generate();
        let recovered = Seed::from_mnemonic(&mnemonic, "");
        assert_eq!(seed.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn passphrase_changes_identity() {
        let (_, mnemonic) = Seed::generate();
        let a = Seed::from_mnemonic(&mnemonic, "");
        let b = Seed::from_mnemonic(&mnemonic, "passphrase");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn mnemonic_is_24_words() {
        let (_, mnemonic) = Seed::generate();
        let count = mnemonic.to_string().split_whitespace().count();
        assert_eq!(count, 24);
    }

    #[test]
    fn debug_redacts_seed() {
        let (seed, _) = Seed::generate();
        let debug = format!("{:?}", seed);
        assert!(debug.contains("REDACTED"));
    }
}
