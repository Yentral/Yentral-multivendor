//! Authenticated encryption with associated data (AEAD).
//!
//! ChaCha20-Poly1305 — RFC 8439. 256-bit key, 96-bit nonce, 128-bit tag.
//!
//! Used by the Double Ratchet to encrypt each message key's output. The
//! *nonce* is derived from the symmetric-ratchet message counter, so the
//! caller does not need to manage nonces manually as long as each message
//! key is used at most once (which the ratchet guarantees).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::CryptoError;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Seal `plaintext` under `key` with `nonce` and `associated_data`.
///
/// Returns `ciphertext || tag`. The nonce MUST be unique per key: reusing a
/// nonce with the same key breaks confidentiality and authenticity.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::KeyDerivation)
}

/// Open `ciphertext` (which includes the trailing tag) under `key` and
/// `associated_data`. Returns plaintext on success, an error on MAC failure.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let plaintext = b"the quick brown phantom";
        let ad = b"PHANTOM/v1";

        let ct = seal(&key, &nonce, plaintext, ad).unwrap();
        let pt = open(&key, &nonce, &ct, ad).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
    }

    #[test]
    fn wrong_key_fails() {
        let ct = seal(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], b"hi", b"").unwrap();
        assert!(open(&[8u8; KEY_LEN], &[1u8; NONCE_LEN], &ct, b"").is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let ct = seal(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], b"hi", b"").unwrap();
        assert!(open(&[7u8; KEY_LEN], &[2u8; NONCE_LEN], &ct, b"").is_err());
    }

    #[test]
    fn wrong_ad_fails() {
        let ct = seal(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], b"hi", b"good").unwrap();
        assert!(open(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], &ct, b"bad").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = seal(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], b"hello", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&[7u8; KEY_LEN], &[1u8; NONCE_LEN], &ct, b"").is_err());
    }
}
