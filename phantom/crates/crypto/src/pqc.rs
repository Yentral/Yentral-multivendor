//! Post-quantum primitives — NIST FIPS 203 / 204 via RustCrypto.
//!
//! - **ML-KEM-1024** (Kyber1024)  — 1568-byte pubkey, 3168-byte secret, quantum-resistant KEM
//! - **ML-DSA-65**   (Dilithium3) — 1952-byte pubkey, 4032-byte secret, quantum-resistant sig
//!
//! Keys are generated from a caller-supplied 32-byte seed via ChaCha20Rng.
//! Given the same seed you always get the same keypair — which is what makes
//! the PHANTOM identity fully mnemonic-recoverable, including its PQ half.
//!
//! Pure-Rust implementations (no C FFI).

use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen as MlDsaKeyGen,
    KeyPair as MlDsaKeyPair, MlDsa65, Signature as MlDsaSignatureT, SigningKey as MlDsaSk,
    VerifyingKey as MlDsaVk,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem1024,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use signature::{Signer as SigSigner, Verifier as SigVerifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// ML-KEM-1024
// ---------------------------------------------------------------------------

pub const MLKEM1024_PUBKEY_LEN:         usize = 1568;
pub const MLKEM1024_SECKEY_LEN:         usize = 3168;
pub const MLKEM1024_CIPHERTEXT_LEN:     usize = 1568;
pub const MLKEM1024_SHARED_SECRET_LEN:  usize = 32;

type MlKem1024Ek = <MlKem1024 as KemCore>::EncapsulationKey;
type MlKem1024Dk = <MlKem1024 as KemCore>::DecapsulationKey;

/// ML-KEM-1024 public key (encapsulation key), 1568 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPublicKey(pub(crate) Vec<u8>);

impl MlKemPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MLKEM1024_PUBKEY_LEN {
            return Err(CryptoError::PqKeyGen);
        }
        Ok(MlKemPublicKey(bytes.to_vec()))
    }

    fn to_ek(&self) -> Result<MlKem1024Ek, CryptoError> {
        let enc: &Encoded<MlKem1024Ek> =
            self.0.as_slice().try_into().map_err(|_| CryptoError::PqKeyGen)?;
        Ok(<MlKem1024Ek as EncodedSizeUser>::from_bytes(enc))
    }
}

/// ML-KEM-1024 secret key (decapsulation key), 3168 bytes. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(pub(crate) Vec<u8>);

impl MlKemSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn to_dk(&self) -> Result<MlKem1024Dk, CryptoError> {
        let enc: &Encoded<MlKem1024Dk> =
            self.0.as_slice().try_into().map_err(|_| CryptoError::PqKeyGen)?;
        Ok(<MlKem1024Dk as EncodedSizeUser>::from_bytes(enc))
    }
}

pub struct MlKem;

impl MlKem {
    /// Generate an ML-KEM-1024 keypair deterministically from a 32-byte seed.
    ///
    /// Uses ChaCha20Rng seeded with the input — a CSPRNG chosen for its
    /// cross-platform determinism. Same seed → same keypair, everywhere.
    pub fn keypair_from_seed(seed: &[u8; 32]) -> (MlKemPublicKey, MlKemSecretKey) {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (dk, ek) = MlKem1024::generate(&mut rng);
        let pk = ek.as_bytes().to_vec();
        let sk = dk.as_bytes().to_vec();
        (MlKemPublicKey(pk), MlKemSecretKey(sk))
    }

    /// Encapsulate a fresh shared secret to the recipient's public key.
    /// Returns (ciphertext, 32-byte shared secret).
    pub fn encapsulate(
        pk: &MlKemPublicKey,
    ) -> Result<(Vec<u8>, [u8; MLKEM1024_SHARED_SECRET_LEN]), CryptoError> {
        let ek = pk.to_ek()?;
        let mut rng = rand::thread_rng();
        let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| CryptoError::PqKeyGen)?;
        let mut shared = [0u8; MLKEM1024_SHARED_SECRET_LEN];
        shared.copy_from_slice(ss.as_slice());
        Ok((ct.as_slice().to_vec(), shared))
    }

    /// Decapsulate a ciphertext using the recipient's secret key.
    pub fn decapsulate(
        sk: &MlKemSecretKey,
        ct_bytes: &[u8],
    ) -> Result<[u8; MLKEM1024_SHARED_SECRET_LEN], CryptoError> {
        let dk = sk.to_dk()?;
        let ct: &ml_kem::Ciphertext<MlKem1024> =
            ct_bytes.try_into().map_err(|_| CryptoError::PqKeyGen)?;
        let ss = dk.decapsulate(ct).map_err(|_| CryptoError::PqKeyGen)?;
        let mut shared = [0u8; MLKEM1024_SHARED_SECRET_LEN];
        shared.copy_from_slice(ss.as_slice());
        Ok(shared)
    }
}

// ---------------------------------------------------------------------------
// ML-DSA-65
// ---------------------------------------------------------------------------

pub const MLDSA65_PUBKEY_LEN:    usize = 1952;
pub const MLDSA65_SECKEY_LEN:    usize = 4032;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 public key (verifying key), 1952 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaPublicKey(pub(crate) Vec<u8>);

impl MlDsaPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MLDSA65_PUBKEY_LEN {
            return Err(CryptoError::PqKeyGen);
        }
        Ok(MlDsaPublicKey(bytes.to_vec()))
    }

    fn to_vk(&self) -> Result<MlDsaVk<MlDsa65>, CryptoError> {
        let enc: &EncodedVerifyingKey<MlDsa65> =
            self.0.as_slice().try_into().map_err(|_| CryptoError::PqKeyGen)?;
        Ok(MlDsaVk::<MlDsa65>::decode(enc))
    }
}

/// ML-DSA-65 secret key (signing key), 4032 bytes. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(pub(crate) Vec<u8>);

impl MlDsaSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn to_sk(&self) -> Result<MlDsaSk<MlDsa65>, CryptoError> {
        let enc: &EncodedSigningKey<MlDsa65> =
            self.0.as_slice().try_into().map_err(|_| CryptoError::PqKeyGen)?;
        Ok(MlDsaSk::<MlDsa65>::decode(enc))
    }
}

pub struct MlDsa;

impl MlDsa {
    /// Generate an ML-DSA-65 keypair deterministically from a 32-byte seed.
    pub fn keypair_from_seed(seed: &[u8; 32]) -> (MlDsaPublicKey, MlDsaSecretKey) {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let kp: MlDsaKeyPair<MlDsa65> = <MlDsa65 as MlDsaKeyGen>::key_gen(&mut rng);
        let pk = kp.verifying_key().encode().to_vec();
        let sk = kp.signing_key().encode().to_vec();
        (MlDsaPublicKey(pk), MlDsaSecretKey(sk))
    }

    /// Produce a detached signature over `message`. Deterministic variant
    /// (empty context string) for reproducible test vectors.
    pub fn sign(sk: &MlDsaSecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signing_key = sk.to_sk()?;
        let sig: MlDsaSignatureT<MlDsa65> = signing_key.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a detached signature. Returns Ok(()) on success.
    pub fn verify(
        pk: &MlDsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let verifying_key = pk.to_vk()?;
        let enc: &EncodedSignature<MlDsa65> = signature
            .try_into()
            .map_err(|_| CryptoError::BadSignature)?;
        let sig = MlDsaSignatureT::<MlDsa65>::decode(enc).ok_or(CryptoError::BadSignature)?;
        verifying_key
            .verify(message, &sig)
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
    fn mlkem_deterministic_keygen() {
        let seed = [7u8; 32];
        let (pk1, sk1) = MlKem::keypair_from_seed(&seed);
        let (pk2, sk2) = MlKem::keypair_from_seed(&seed);
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
        assert_eq!(pk1.as_bytes().len(), MLKEM1024_PUBKEY_LEN);
        assert_eq!(sk1.as_bytes().len(), MLKEM1024_SECKEY_LEN);
    }

    #[test]
    fn mlkem_different_seeds_yield_different_keys() {
        let (pk_a, _) = MlKem::keypair_from_seed(&[0u8; 32]);
        let (pk_b, _) = MlKem::keypair_from_seed(&[1u8; 32]);
        assert_ne!(pk_a.as_bytes(), pk_b.as_bytes());
    }

    #[test]
    fn mlkem_encapsulate_decapsulate_roundtrip() {
        let (pk, sk) = MlKem::keypair_from_seed(&[42u8; 32]);
        let (ct, ss_a) = MlKem::encapsulate(&pk).unwrap();
        let ss_b = MlKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
        assert_eq!(ct.len(), MLKEM1024_CIPHERTEXT_LEN);
    }

    #[test]
    fn mldsa_deterministic_keygen() {
        let seed = [9u8; 32];
        let (pk1, sk1) = MlDsa::keypair_from_seed(&seed);
        let (pk2, sk2) = MlDsa::keypair_from_seed(&seed);
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
        assert_eq!(pk1.as_bytes().len(), MLDSA65_PUBKEY_LEN);
    }

    #[test]
    fn mldsa_sign_verify_roundtrip() {
        let (pk, sk) = MlDsa::keypair_from_seed(&[1u8; 32]);
        let msg = b"PHANTOM Protocol";
        let sig = MlDsa::sign(&sk, msg).unwrap();
        MlDsa::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn mldsa_tampered_message_fails() {
        let (pk, sk) = MlDsa::keypair_from_seed(&[2u8; 32]);
        let sig = MlDsa::sign(&sk, b"original").unwrap();
        assert!(MlDsa::verify(&pk, b"tampered", &sig).is_err());
    }
}
