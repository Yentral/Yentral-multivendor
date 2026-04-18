//! Post-quantum primitives — thin wrappers over NIST FIPS 203 / 204.
//!
//! - ML-KEM-1024 (Kyber1024) — key encapsulation, quantum-resistant
//! - ML-DSA-65   (Dilithium3) — digital signatures, quantum-resistant
//!
//! ## Key derivation note
//!
//! Classical keys (Ed25519, X25519) are derived *deterministically* from the
//! master seed via HKDF. For wallet-style recovery, a user who remembers their
//! mnemonic reconstructs the exact same classical keys.
//!
//! ML-KEM and ML-DSA keypairs in Sprint 1 are generated with the OS CSPRNG
//! (non-deterministic). Recovery of the post-quantum keypair relies on having
//! the *encrypted local database* backed up alongside the mnemonic — the
//! storage-encryption key is seed-derived, so a mnemonic + DB backup is
//! sufficient to fully restore.
//!
//! Sprint 2 TODO: switch to FIPS-aligned deterministic keygen (`KeyGen(d,z)`
//! for ML-KEM, `KeyGen(ξ)` for ML-DSA) so that PQ keys also re-derive purely
//! from the mnemonic, eliminating the DB-backup requirement.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedSignature, PublicKey as SignPublicKey,
    SecretKey as SignSecretKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// ML-KEM-1024 (Kyber1024)
// ---------------------------------------------------------------------------

/// ML-KEM-1024 public key (1568 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPublicKey(Vec<u8>);

impl MlKemPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        mlkem1024::PublicKey::from_bytes(bytes)
            .map(|pk| MlKemPublicKey(pk.as_bytes().to_vec()))
            .map_err(|_| CryptoError::PqKeyGen)
    }
}

/// ML-KEM-1024 secret key (3168 bytes). Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(Vec<u8>);

impl MlKemSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlKem;

impl MlKem {
    pub fn keypair() -> (MlKemPublicKey, MlKemSecretKey) {
        let (pk, sk) = mlkem1024::keypair();
        (
            MlKemPublicKey(pk.as_bytes().to_vec()),
            MlKemSecretKey(sk.as_bytes().to_vec()),
        )
    }

    /// Encapsulate a shared secret to the recipient's public key.
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate(pk: &MlKemPublicKey) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
        let pk = mlkem1024::PublicKey::from_bytes(&pk.0).map_err(|_| CryptoError::PqKeyGen)?;
        let (ss, ct) = mlkem1024::encapsulate(&pk);
        let mut shared = [0u8; 32];
        let ss_bytes = ss.as_bytes();
        // ML-KEM shared secret is 32 bytes
        shared.copy_from_slice(&ss_bytes[..32]);
        Ok((ct.as_bytes().to_vec(), shared))
    }

    /// Decapsulate a ciphertext using the recipient's secret key.
    pub fn decapsulate(sk: &MlKemSecretKey, ct: &[u8]) -> Result<[u8; 32], CryptoError> {
        let sk = mlkem1024::SecretKey::from_bytes(&sk.0).map_err(|_| CryptoError::PqKeyGen)?;
        let ct = mlkem1024::Ciphertext::from_bytes(ct).map_err(|_| CryptoError::PqKeyGen)?;
        let ss = mlkem1024::decapsulate(&ct, &sk);
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&ss.as_bytes()[..32]);
        Ok(shared)
    }
}

// ---------------------------------------------------------------------------
// ML-DSA-65 (Dilithium3)
// ---------------------------------------------------------------------------

/// ML-DSA-65 public key (1952 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaPublicKey(Vec<u8>);

impl MlDsaPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        mldsa65::PublicKey::from_bytes(bytes)
            .map(|pk| MlDsaPublicKey(pk.as_bytes().to_vec()))
            .map_err(|_| CryptoError::PqKeyGen)
    }
}

/// ML-DSA-65 secret key (4032 bytes). Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(Vec<u8>);

impl MlDsaSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct MlDsa;

impl MlDsa {
    pub fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
        let (pk, sk) = mldsa65::keypair();
        (
            MlDsaPublicKey(pk.as_bytes().to_vec()),
            MlDsaSecretKey(sk.as_bytes().to_vec()),
        )
    }

    /// Produce a detached signature over `message` using the secret key.
    pub fn sign(sk: &MlDsaSecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = mldsa65::SecretKey::from_bytes(&sk.0).map_err(|_| CryptoError::PqKeyGen)?;
        let sig = mldsa65::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    /// Verify a detached signature. Returns Ok(()) on success.
    pub fn verify(pk: &MlDsaPublicKey, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let pk = mldsa65::PublicKey::from_bytes(&pk.0).map_err(|_| CryptoError::PqKeyGen)?;
        let sig = mldsa65::DetachedSignature::from_bytes(signature)
            .map_err(|_| CryptoError::BadSignature)?;
        mldsa65::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| CryptoError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = MlKem::keypair();
        let (ct, ss_a) = MlKem::encapsulate(&pk).unwrap();
        let ss_b = MlKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn mldsa_sign_verify_roundtrip() {
        let (pk, sk) = MlDsa::keypair();
        let msg = b"PHANTOM Protocol v0.1";
        let sig = MlDsa::sign(&sk, msg).unwrap();
        MlDsa::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn mldsa_wrong_message_fails() {
        let (pk, sk) = MlDsa::keypair();
        let sig = MlDsa::sign(&sk, b"original").unwrap();
        assert!(MlDsa::verify(&pk, b"tampered", &sig).is_err());
    }
}
