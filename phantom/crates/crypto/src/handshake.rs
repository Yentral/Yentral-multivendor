//! PQ-X3DH+ — asynchronous, hybrid key agreement.
//!
//! Extended Triple Diffie-Hellman (Signal's X3DH) combined with ML-KEM-1024
//! encapsulations. Four classical DH values plus two PQ KEM shared secrets
//! are concatenated and fed through HKDF-SHA256 to produce the 32-byte root
//! key from which the Double Ratchet (Sprint-3) will unfold.
//!
//! ```text
//!    Alice (initiator)                 Wire                   Bob (responder)
//!    ────────────────────             ───────                ───────────────
//!
//!    fetch Bob.bundle ────────────────────────────────────►  publishes bundle
//!    verify hybrid sig
//!    EK_x = X25519::new()
//!
//!    dh1 = DH(IK_A.x,  SPK_B.x)
//!    dh2 = DH(EK,      IK_B.x)
//!    dh3 = DH(EK,      SPK_B.x)
//!    dh4 = DH(EK,      OTPK_B.x)
//!    (ct_spk,  ss_spk)  = KEM.enc(SPK_B.mlkem)
//!    (ct_otpk, ss_otpk) = KEM.enc(OTPK_B.mlkem)
//!
//!    SK = HKDF( dh1||dh2||dh3||dh4 ||
//!               ss_spk||ss_otpk,
//!               info="pq-x3dh-root" )
//!
//!    build InitialMessage {
//!       IK_A (hybrid pubs),
//!       EK_x,
//!       spk_id, otpk_id,
//!       ct_spk, ct_otpk,
//!    }                                      ──────────►    parse InitialMessage
//!                                                          look up SPK, OTPK secrets
//!
//!                                                          dh1' = DH(SPK_B.x,  IK_A.x)
//!                                                          dh2' = DH(IK_B.x,  EK_A)
//!                                                          dh3' = DH(SPK_B.x, EK_A)
//!                                                          dh4' = DH(OTPK_B.x,EK_A)
//!                                                          ss_spk  = KEM.dec(..., ct_spk)
//!                                                          ss_otpk = KEM.dec(..., ct_otpk)
//!
//!                                                          SK = HKDF( same IKM )
//!                                                          destroy OTPK
//! ```
//!
//! Security: an attacker must break **both** the X25519 discrete log AND
//! ML-KEM-1024 to recover SK. Forward secrecy is provided by the ephemeral
//! EK and the one-time prekey; post-compromise recovery arrives in Sprint-3
//! with the Double Ratchet.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Pk, StaticSecret as X25519Sk};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::identity::Identity;
use crate::kdf::info;
use crate::pqc::{MlDsaPublicKey, MlKem};
use crate::prekey::{IdentityPubs, OneTimePreKeySecret, PreKeyBundle, SignedPreKeySecret};

/// Output of a successful initiation — both the wire message to send and
/// the resulting 32-byte root key, which seeds the Double Ratchet.
pub struct InitiatorOutput {
    pub initial_message: InitialMessage,
    pub root_key: [u8; 32],
}

/// First message sent by the initiator. Carries everything the responder
/// needs to reconstruct the same root key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialMessage {
    pub sender_identity: IdentityPubs,
    pub ephemeral_x25519: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: u32,
    pub mlkem_ct_spk: Vec<u8>,  // 1568 B
    pub mlkem_ct_otpk: Vec<u8>, // 1568 B
}

// ---------------------------------------------------------------------------
// Initiator (Alice)
// ---------------------------------------------------------------------------

/// Alice begins a session with Bob using Bob's (verified) prekey bundle.
///
/// Returns the wire message to send and the derived 32-byte root key.
pub fn initiate(
    alice: &Identity,
    bob_bundle: &PreKeyBundle,
) -> Result<InitiatorOutput, CryptoError> {
    bob_bundle.verify()?;

    // Alice's ephemeral X25519 keypair.
    let mut eph_seed = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut eph_seed);
    let ek_sk = X25519Sk::from(eph_seed);
    let ek_pk = X25519Pk::from(&ek_sk);
    eph_seed.zeroize();

    // Parse Bob's public pieces.
    let bob_ik_x = X25519Pk::from(bob_bundle.body.identity.x25519);
    let bob_spk_x = X25519Pk::from(bob_bundle.body.signed_prekey.x25519_pub);
    let bob_otpk_x = X25519Pk::from(bob_bundle.body.one_time_prekey.x25519_pub);
    let bob_spk_mlkem =
        crate::pqc::MlKemPublicKey::from_bytes(&bob_bundle.body.signed_prekey.mlkem1024_pub)?;
    let bob_otpk_mlkem =
        crate::pqc::MlKemPublicKey::from_bytes(&bob_bundle.body.one_time_prekey.mlkem1024_pub)?;

    // DH values.
    let dh1 = alice.x25519_sk.diffie_hellman(&bob_spk_x);
    let dh2 = ek_sk.diffie_hellman(&bob_ik_x);
    let dh3 = ek_sk.diffie_hellman(&bob_spk_x);
    let dh4 = ek_sk.diffie_hellman(&bob_otpk_x);

    // KEM encapsulations.
    let (ct_spk, ss_spk) = MlKem::encapsulate(&bob_spk_mlkem)?;
    let (ct_otpk, ss_otpk) = MlKem::encapsulate(&bob_otpk_mlkem)?;

    // Assemble IKM and derive root key.
    let mut ikm = Vec::with_capacity(32 * 6);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());
    ikm.extend_from_slice(&ss_spk);
    ikm.extend_from_slice(&ss_otpk);

    let root_key = derive_root_key(&ikm)?;
    ikm.zeroize();

    let initial_message = InitialMessage {
        sender_identity: IdentityPubs::from_identity(alice),
        ephemeral_x25519: *ek_pk.as_bytes(),
        signed_prekey_id: bob_bundle.body.signed_prekey.id,
        one_time_prekey_id: bob_bundle.body.one_time_prekey.id,
        mlkem_ct_spk: ct_spk,
        mlkem_ct_otpk: ct_otpk,
    };

    Ok(InitiatorOutput {
        initial_message,
        root_key,
    })
}

// ---------------------------------------------------------------------------
// Responder (Bob)
// ---------------------------------------------------------------------------

/// Bob reconstructs the root key when he receives Alice's InitialMessage.
///
/// He must present the secret halves of the exact prekeys Alice used —
/// identified by `signed_prekey_id` and `one_time_prekey_id` in the message.
///
/// After this call, the one-time prekey MUST be destroyed (and removed from
/// any published bundle) so it cannot be reused.
pub fn respond(
    bob: &Identity,
    spk_secret: &SignedPreKeySecret,
    otpk_secret: &OneTimePreKeySecret,
    msg: &InitialMessage,
) -> Result<[u8; 32], CryptoError> {
    if spk_secret.id != msg.signed_prekey_id {
        return Err(CryptoError::KeyDerivation);
    }
    if otpk_secret.id != msg.one_time_prekey_id {
        return Err(CryptoError::KeyDerivation);
    }

    // Optional but cheap: verify Alice's claimed hybrid identity by checking
    // her MLDSA65 pubkey is well-formed. Signature-over-message binding is
    // Sprint-3's job (the first AEAD-sealed payload includes a handshake-MAC).
    let _ = MlDsaPublicKey::from_bytes(&msg.sender_identity.mldsa65)?;
    let _ = ed25519_dalek::VerifyingKey::from_bytes(&msg.sender_identity.ed25519)
        .map_err(|_| CryptoError::BadSignature)?;

    // Alice's pieces.
    let alice_ik_x = X25519Pk::from(msg.sender_identity.x25519);
    let alice_ek_x = X25519Pk::from(msg.ephemeral_x25519);

    // Mirror DH operations.
    let dh1 = spk_secret.x25519_sk.diffie_hellman(&alice_ik_x);
    let dh2 = bob.x25519_sk.diffie_hellman(&alice_ek_x);
    let dh3 = spk_secret.x25519_sk.diffie_hellman(&alice_ek_x);
    let dh4 = otpk_secret.x25519_sk.diffie_hellman(&alice_ek_x);

    // Mirror KEM decapsulations.
    let ss_spk = MlKem::decapsulate(&spk_secret.mlkem_sk, &msg.mlkem_ct_spk)?;
    let ss_otpk = MlKem::decapsulate(&otpk_secret.mlkem_sk, &msg.mlkem_ct_otpk)?;

    let mut ikm = Vec::with_capacity(32 * 6);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());
    ikm.extend_from_slice(&ss_spk);
    ikm.extend_from_slice(&ss_otpk);

    let root_key = derive_root_key(&ikm)?;
    ikm.zeroize();

    // Note: the caller is responsible for deleting `otpk_secret` after this
    // returns. We do not drop it here because the borrow is immutable.
    Ok(root_key)
}

// ---------------------------------------------------------------------------
// Root-key KDF
// ---------------------------------------------------------------------------

fn derive_root_key(ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut sk = [0u8; 32];
    hk.expand(info::X3DH_ROOT, &mut sk)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(sk)
}
