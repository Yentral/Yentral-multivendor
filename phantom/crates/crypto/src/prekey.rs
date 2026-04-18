//! PreKey bundle — what a user publishes so others can start a session
//! with them while they are offline.
//!
//! ```text
//!   ┌──────────────────────────────── signed ────────────────────────────┐
//!   │                                                                    │
//!   │  identity:                                                         │
//!   │    ed25519_ik, x25519_ik, mldsa_ik, mlkem_ik                       │
//!   │                                                                    │
//!   │  signed_prekey:                                                    │
//!   │    id, x25519_spk, mlkem_spk                                       │
//!   │                                                                    │
//!   │  one_time_prekey:                                                  │
//!   │    id, x25519_otpk, mlkem_otpk                                     │
//!   │                                                                    │
//!   │  timestamp_hour, protocol_version                                  │
//!   │                                                                    │
//!   └────────────────────────────────────────────────────────────────────┘
//!                              │
//!                Canonical bincode → BLAKE3 domain-separated hash
//!                              │
//!             ┌────────────────┴────────────────┐
//!             ▼                                 ▼
//!        Ed25519 sign                      ML-DSA-65 sign
//!        (classical)                       (post-quantum)
//! ```
//!
//! Verifier must check **both** signatures. Hybrid security: an attacker
//! needs to break BOTH the classical and the PQ signature scheme.

use ed25519_dalek::{Signature as EdSig, Signer as EdSigner, Verifier as EdVerifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::identity::Identity;
use crate::pqc::{MlDsa, MlDsaPublicKey, MlKem, MlKemSecretKey};

pub const PHANTOM_PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Public bundle (published to DHT / server)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPubs {
    pub ed25519:   [u8; 32],
    pub x25519:    [u8; 32],
    pub mldsa65:   Vec<u8>, // 1952 B
    pub mlkem1024: Vec<u8>, // 1568 B
}

impl IdentityPubs {
    pub fn from_identity(id: &Identity) -> Self {
        Self {
            ed25519:   *id.ed25519_pk.as_bytes(),
            x25519:    *id.x25519_pk.as_bytes(),
            mldsa65:   id.mldsa65_pk.as_bytes().to_vec(),
            mlkem1024: id.mlkem1024_pk.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPreKeyPub {
    pub id:            u32,
    pub x25519_pub:    [u8; 32],
    pub mlkem1024_pub: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePreKeyPub {
    pub id:            u32,
    pub x25519_pub:    [u8; 32],
    pub mlkem1024_pub: Vec<u8>,
}

/// Everything inside the signed envelope — i.e., the body over which the
/// hybrid signature is computed. Signatures live in the outer `PreKeyBundle`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleBody {
    pub protocol_version: u32,
    pub timestamp_hour:   u64,
    pub identity:         IdentityPubs,
    pub signed_prekey:    SignedPreKeyPub,
    pub one_time_prekey:  OneTimePreKeyPub,
}

/// The dual (Ed25519 + ML-DSA-65) signature over the canonical bundle body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519_sig: Vec<u8>, // 64 B
    pub mldsa65_sig: Vec<u8>, // 3309 B
}

/// The full published bundle: body + hybrid signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub body:       BundleBody,
    pub signatures: HybridSignature,
}

// ---------------------------------------------------------------------------
// Secret side — Bob's private half, kept on device
// ---------------------------------------------------------------------------

/// Secret material behind a published signed prekey.
///
/// Bob keeps the X25519 secret (for DH) and ML-KEM secret (for decapsulation)
/// for as long as the prekey remains published. Rotates weekly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeySecret {
    pub id: u32,
    #[zeroize(skip)] // x25519_dalek zeros its own secret on drop
    pub x25519_sk: x25519_dalek::StaticSecret,
    pub mlkem_sk:  MlKemSecretKey,
}

/// Secret material behind a published one-time prekey. Consumed after a
/// single handshake.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OneTimePreKeySecret {
    pub id: u32,
    #[zeroize(skip)]
    pub x25519_sk: x25519_dalek::StaticSecret,
    pub mlkem_sk:  MlKemSecretKey,
}

// ---------------------------------------------------------------------------
// Bundle builder — sign and publish
// ---------------------------------------------------------------------------

/// What Bob keeps locally after publishing: the bundle itself (for reference)
/// plus the secret halves needed to answer incoming handshakes.
pub struct PublishedBundle {
    pub public:          PreKeyBundle,
    pub signed_prekey:   SignedPreKeySecret,
    pub one_time_prekey: OneTimePreKeySecret,
}

impl PreKeyBundle {
    /// Build a fresh bundle for `identity`, generate one signed prekey and
    /// one one-time prekey, sign the whole thing with the hybrid signature,
    /// and return both the public and secret halves.
    ///
    /// `now_hour` = current unix time rounded down to the hour. Passed in so
    /// that tests can use fixed values and clients can feed their own clock.
    pub fn build(
        identity: &Identity,
        signed_prekey_id: u32,
        one_time_prekey_id: u32,
        now_hour: u64,
    ) -> Result<PublishedBundle, CryptoError> {
        let mut rng = rand::thread_rng();

        // Generate fresh signed prekey (classical + PQ).
        let mut x_spk_seed = [0u8; 32];
        rng.fill_bytes(&mut x_spk_seed);
        let x_spk_sk = x25519_dalek::StaticSecret::from(x_spk_seed);
        let x_spk_pk = x25519_dalek::PublicKey::from(&x_spk_sk);

        let mut pq_spk_seed = [0u8; 32];
        rng.fill_bytes(&mut pq_spk_seed);
        let (pq_spk_pk, pq_spk_sk) = MlKem::keypair_from_seed(&pq_spk_seed);

        // Generate fresh one-time prekey (classical + PQ).
        let mut x_otpk_seed = [0u8; 32];
        rng.fill_bytes(&mut x_otpk_seed);
        let x_otpk_sk = x25519_dalek::StaticSecret::from(x_otpk_seed);
        let x_otpk_pk = x25519_dalek::PublicKey::from(&x_otpk_sk);

        let mut pq_otpk_seed = [0u8; 32];
        rng.fill_bytes(&mut pq_otpk_seed);
        let (pq_otpk_pk, pq_otpk_sk) = MlKem::keypair_from_seed(&pq_otpk_seed);

        let body = BundleBody {
            protocol_version: PHANTOM_PROTOCOL_VERSION,
            timestamp_hour:   now_hour,
            identity:         IdentityPubs::from_identity(identity),
            signed_prekey: SignedPreKeyPub {
                id:            signed_prekey_id,
                x25519_pub:    *x_spk_pk.as_bytes(),
                mlkem1024_pub: pq_spk_pk.as_bytes().to_vec(),
            },
            one_time_prekey: OneTimePreKeyPub {
                id:            one_time_prekey_id,
                x25519_pub:    *x_otpk_pk.as_bytes(),
                mlkem1024_pub: pq_otpk_pk.as_bytes().to_vec(),
            },
        };

        let signatures = sign_bundle_body(identity, &body)?;

        let public = PreKeyBundle { body, signatures };

        Ok(PublishedBundle {
            public,
            signed_prekey: SignedPreKeySecret {
                id:        signed_prekey_id,
                x25519_sk: x_spk_sk,
                mlkem_sk:  pq_spk_sk,
            },
            one_time_prekey: OneTimePreKeySecret {
                id:        one_time_prekey_id,
                x25519_sk: x_otpk_sk,
                mlkem_sk:  pq_otpk_sk,
            },
        })
    }

    /// Verify the hybrid signature using the identity public keys embedded
    /// in the body. Returns Ok(()) only if **both** signatures check out.
    pub fn verify(&self) -> Result<(), CryptoError> {
        // The identity pubs inside body claim authorship; verify against them.
        let ed_pk = ed25519_dalek::VerifyingKey::from_bytes(&self.body.identity.ed25519)
            .map_err(|_| CryptoError::BadSignature)?;
        let mldsa_pk = MlDsaPublicKey::from_bytes(&self.body.identity.mldsa65)?;

        let msg = canonical_body_bytes(&self.body)?;

        let ed_sig = EdSig::from_slice(&self.signatures.ed25519_sig)
            .map_err(|_| CryptoError::BadSignature)?;
        ed_pk
            .verify(&msg, &ed_sig)
            .map_err(|_| CryptoError::BadSignature)?;

        MlDsa::verify(&mldsa_pk, &msg, &self.signatures.mldsa65_sig)?;

        Ok(())
    }
}

/// Canonical byte encoding of the body for signing/verifying. Bincode's
/// default little-endian fixed-int config is deterministic across platforms,
/// which is what we need.
fn canonical_body_bytes(body: &BundleBody) -> Result<Vec<u8>, CryptoError> {
    let serialized =
        bincode::serialize(body).map_err(|_| CryptoError::KeyDerivation)?;
    // Domain-separate so bundle bytes can never be confused with anything else.
    let mut h = blake3::Hasher::new();
    h.update(crate::kdf::info::PREKEY_BUNDLE_SIG);
    h.update(&serialized);
    // Return both the domain tag and the bundle for signing, via the hash
    // as a compact, fixed-size canonical representation.
    Ok(h.finalize().as_bytes().to_vec())
}

fn sign_bundle_body(identity: &Identity, body: &BundleBody) -> Result<HybridSignature, CryptoError> {
    let msg = canonical_body_bytes(body)?;

    let ed_sig: EdSig = identity.ed25519_sk.sign(&msg);
    let ed_sig_bytes = ed_sig.to_bytes().to_vec();

    let mldsa_sig = MlDsa::sign(&identity.mldsa65_sk, &msg)?;

    Ok(HybridSignature {
        ed25519_sig: ed_sig_bytes,
        mldsa65_sig: mldsa_sig,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed;

    fn fixed_identity() -> Identity {
        let seed = Seed::from_mnemonic(
            &Seed::parse_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon art",
            )
            .unwrap(),
            "",
        );
        Identity::from_seed(&seed).unwrap()
    }

    #[test]
    fn bundle_signs_and_verifies() {
        let id = fixed_identity();
        let published = PreKeyBundle::build(&id, 1, 100, 1_700_000_000).unwrap();
        published.public.verify().unwrap();
    }

    #[test]
    fn bundle_tampered_body_fails_verification() {
        let id = fixed_identity();
        let mut published = PreKeyBundle::build(&id, 1, 100, 1_700_000_000).unwrap();
        // Flip one byte of the signed prekey.
        published.public.body.signed_prekey.x25519_pub[0] ^= 0x01;
        assert!(published.public.verify().is_err());
    }

    #[test]
    fn bundle_tampered_ed25519_sig_fails() {
        let id = fixed_identity();
        let mut published = PreKeyBundle::build(&id, 1, 100, 1_700_000_000).unwrap();
        published.public.signatures.ed25519_sig[0] ^= 0x01;
        assert!(published.public.verify().is_err());
    }

    #[test]
    fn bundle_tampered_mldsa_sig_fails() {
        let id = fixed_identity();
        let mut published = PreKeyBundle::build(&id, 1, 100, 1_700_000_000).unwrap();
        published.public.signatures.mldsa65_sig[0] ^= 0x01;
        assert!(published.public.verify().is_err());
    }

    #[test]
    fn bundle_substituted_identity_fails() {
        let id_a = fixed_identity();
        let published = PreKeyBundle::build(&id_a, 1, 100, 1_700_000_000).unwrap();

        // Attacker: rewrite the identity to someone else's pubs, keep sigs.
        let (other_seed, _) = Seed::generate();
        let id_b = Identity::from_seed(&other_seed).unwrap();
        let mut forged = published.public.clone();
        forged.body.identity = IdentityPubs::from_identity(&id_b);

        // Signatures were over the original body; verification against the
        // new identity pubs must fail.
        assert!(forged.verify().is_err());
    }
}
