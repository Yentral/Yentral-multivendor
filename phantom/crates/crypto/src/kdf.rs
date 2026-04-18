//! Key derivation helpers.
//!
//! All sub-keys derived from the master seed use HKDF-SHA256 with a
//! protocol-scoped info string. Info strings are versioned so that future
//! protocol upgrades never collide with existing keys.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

/// HKDF-SHA256 with an empty salt. Returns `N` output bytes.
pub fn hkdf_expand<const N: usize>(ikm: &[u8], info: &[u8]) -> Result<[u8; N], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(out)
}

/// Domain separation tags. Every sub-key MUST use its own tag; never reuse.
pub mod info {
    pub const ED25519_SIGN:    &[u8] = b"phantom/v1/ed25519-sign";
    pub const X25519_KEM:      &[u8] = b"phantom/v1/x25519-kem";
    pub const MLDSA65_SIGN:    &[u8] = b"phantom/v1/mldsa65-sign-drbg";
    pub const MLKEM1024_KEM:   &[u8] = b"phantom/v1/mlkem1024-kem-drbg";
    pub const STORAGE:         &[u8] = b"phantom/v1/local-storage";
    pub const FINGERPRINT:     &[u8] = b"phantom/v1/fingerprint";
}
