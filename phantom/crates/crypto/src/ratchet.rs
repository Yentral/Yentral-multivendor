//! Double Ratchet — the post-handshake encryption state machine.
//!
//! After PQ-X3DH+ hands off a 32-byte root key, both parties feed it into
//! a Session and exchange messages. Each message advances a *symmetric
//! ratchet* (chain key → message key) and, whenever a party sends the first
//! message after receiving, it *also* advances a *DH ratchet*: a fresh
//! X25519 keypair is generated and included in the header, feeding fresh
//! entropy into the root-key chain. This gives:
//!
//! - **Forward secrecy**: compromise of a current key does not reveal past messages.
//! - **Post-compromise security**: after a DH ratchet step, the attacker
//!   can no longer read new messages even if they had the previous key.
//!
//! ## Scope of Sprint 3
//!
//! The ratchet rotates **X25519** at every DH step. The initial PQ
//! randomness (ML-KEM-1024 shared secrets) is mixed into the root key by
//! the X3DH+ handshake; a full PQ re-key is triggered by running a fresh
//! X3DH+ handshake (periodic "session reset"), not by interleaving PQ into
//! every ratchet step. Rationale: including a 1.5 KB Kyber ciphertext in
//! every message header blows up bandwidth ~30× for little gain; periodic
//! re-handshaking is what Signal does with PQXDH today.
//!
//! ## State machine (simplified)
//!
//! ```text
//!                Root key (from X3DH+)
//!                        │
//!                        ▼
//!   ┌────────── Diffie-Hellman ratchet ──────────┐
//!   │  HKDF(root, DH(us_sk, them_pk))            │
//!   │    → new root                              │
//!   │    → new chain key (send or receive)       │
//!   └────────────────────────────────────────────┘
//!                        │
//!                        ▼
//!   ┌─────────── Symmetric ratchet ──────────────┐
//!   │  chain_key ──HKDF──► next_chain_key        │
//!   │               └───► message_key            │
//!   └────────────────────────────────────────────┘
//!                        │
//!                        ▼
//!         AEAD.seal(message_key, nonce, payload, ad)
//! ```

use std::collections::HashMap;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Pk, StaticSecret as X25519Sk};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead;
use crate::error::CryptoError;
use crate::kdf::info;

/// Cap on the number of skipped message keys we'll retain per session.
/// Prevents a malicious counter-party from making us allocate unbounded
/// memory by claiming huge message counters.
pub const MAX_SKIPPED_MESSAGE_KEYS: u32 = 1024;

/// Cap on how far ahead of the current counter a single arriving message
/// can jump. Stops a single malformed header from triggering 2^32 skipped
/// keys derivations.
pub const MAX_SKIP_PER_STEP: u32 = 256;

// ---------------------------------------------------------------------------
// Message header and wire message
// ---------------------------------------------------------------------------

/// Plaintext header, bound into the AEAD as associated data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key (X25519, 32 B).
    pub sender_dh: [u8; 32],
    /// Number of messages in the *previous* sending chain (needed so the
    /// receiver knows how many skipped keys to pre-compute on a DH step).
    pub previous_chain_length: u32,
    /// Zero-based counter within the current sending chain.
    pub message_counter: u32,
}

impl RatchetHeader {
    fn associated_data(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RatchetHeader is fixed-size serializable")
    }
}

/// A wire-format encrypted message produced by `Session::encrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Session — the Double Ratchet state
// ---------------------------------------------------------------------------

/// The per-peer Double Ratchet state.
///
/// `Session` is **stateful**: every call to `encrypt` or `decrypt` mutates it
/// (advancing chain keys, rotating DH pairs). Persist it across process
/// restarts or the party loses the ability to read further messages.
pub struct Session {
    /// The root-key chain. Advanced on every DH ratchet step.
    root_key: [u8; 32],

    /// Our current sending DH private key. None until the first send.
    sending_dh_sk: X25519Sk,

    /// Our current sending DH public key (derived from `sending_dh_sk`).
    sending_dh_pk: X25519Pk,

    /// Remote's current DH public key. None for the initiator before they've
    /// received a reply (Alice only has Bob's long-term IK_x from X3DH).
    remote_dh_pk: Option<X25519Pk>,

    /// Sending chain key. None until a DH step has seeded it (for Alice this
    /// happens immediately on init from root; for Bob it seeds on his first
    /// send, after receiving Alice's first message).
    sending_chain: Option<ChainKey>,

    /// Counter for the sending chain.
    sending_counter: u32,

    /// Number of messages sent under the *previous* sending chain. Gets
    /// shipped in every outgoing header so the receiver can keep up.
    previous_sending_counter: u32,

    /// Receiving chain key. None until we receive our first message.
    receiving_chain: Option<ChainKey>,

    /// Counter for the receiving chain.
    receiving_counter: u32,

    /// Skipped message keys from earlier chains, indexed by
    /// (sender_dh_pub, counter). Bounded by `MAX_SKIPPED_MESSAGE_KEYS`.
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

/// A 32-byte chain key. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ChainKey(pub [u8; 32]);

impl Session {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Alice-side (initiator) construction.
    ///
    /// Called right after `handshake::initiate` yields its 32-byte root key.
    /// Alice immediately performs a DH step against Bob's identity X25519
    /// pubkey so she can seed her sending chain and send the first message.
    pub fn alice_from_root(
        root_key: [u8; 32],
        bob_identity_x25519: X25519Pk,
    ) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let sending_sk = X25519Sk::from(seed);
        let sending_pk = X25519Pk::from(&sending_sk);

        let (new_root, send_chain) =
            kdf_rk(&root_key, &sending_sk.diffie_hellman(&bob_identity_x25519))?;

        Ok(Self {
            root_key: new_root,
            sending_dh_sk: sending_sk,
            sending_dh_pk: sending_pk,
            remote_dh_pk: Some(bob_identity_x25519),
            sending_chain: Some(ChainKey(send_chain)),
            sending_counter: 0,
            previous_sending_counter: 0,
            receiving_chain: None,
            receiving_counter: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Bob-side (responder) construction.
    ///
    /// Called right after `handshake::respond` yields its 32-byte root key.
    /// Bob's sending chain is not seeded until he receives Alice's first
    /// message (which carries her ephemeral DH pubkey); he keeps his
    /// identity X25519 secret for the initial DH step that Alice already
    /// performed on her side.
    pub fn bob_from_root(root_key: [u8; 32], bob_identity_x25519_sk: X25519Sk) -> Self {
        let bob_identity_x25519_pk = X25519Pk::from(&bob_identity_x25519_sk);
        Self {
            root_key,
            sending_dh_sk: bob_identity_x25519_sk,
            sending_dh_pk: bob_identity_x25519_pk,
            remote_dh_pk: None,
            sending_chain: None,
            sending_counter: 0,
            previous_sending_counter: 0,
            receiving_chain: None,
            receiving_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Encrypt
    // -----------------------------------------------------------------------

    /// Encrypt a message, advancing the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
        let chain = self
            .sending_chain
            .as_ref()
            .ok_or(CryptoError::KeyDerivation)?;

        let (next_chain_key, msg_key) = kdf_ck(&chain.0)?;
        let counter = self.sending_counter;
        self.sending_chain = Some(ChainKey(next_chain_key));
        self.sending_counter += 1;

        let header = RatchetHeader {
            sender_dh: *self.sending_dh_pk.as_bytes(),
            previous_chain_length: self.previous_sending_counter,
            message_counter: counter,
        };
        let ad = header.associated_data();
        let nonce = counter_to_nonce(counter);

        let ciphertext = aead::seal(&msg_key, &nonce, plaintext, &ad)?;

        Ok(RatchetMessage { header, ciphertext })
    }

    // -----------------------------------------------------------------------
    // Decrypt
    // -----------------------------------------------------------------------

    /// Decrypt a message, advancing the receiving chain and rotating the
    /// DH ratchet if the sender has advanced theirs.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        // 1. Already-skipped key?
        let key_id = (msg.header.sender_dh, msg.header.message_counter);
        if let Some(msg_key) = self.skipped_keys.remove(&key_id) {
            return decrypt_with_key(&msg_key, msg);
        }

        // 2. New DH ratchet step?
        let incoming_dh = X25519Pk::from(msg.header.sender_dh);
        let dh_changed = match self.remote_dh_pk {
            Some(current) => current.as_bytes() != incoming_dh.as_bytes(),
            None => true,
        };

        if dh_changed {
            // Finish skipping keys in the old receiving chain up to
            // previous_chain_length, so out-of-order messages from the old
            // chain can still be decrypted later.
            self.skip_message_keys(msg.header.previous_chain_length)?;

            // Perform DH ratchet.
            let (new_root, recv_chain) = kdf_rk(
                &self.root_key,
                &self.sending_dh_sk.diffie_hellman(&incoming_dh),
            )?;
            self.root_key = new_root;
            self.receiving_chain = Some(ChainKey(recv_chain));
            self.receiving_counter = 0;
            self.remote_dh_pk = Some(incoming_dh);

            // Generate our own new sending DH pair and advance the root/chain.
            let mut seed = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut seed);
            let new_sending_sk = X25519Sk::from(seed);
            let new_sending_pk = X25519Pk::from(&new_sending_sk);

            let (new_root2, send_chain) =
                kdf_rk(&self.root_key, &new_sending_sk.diffie_hellman(&incoming_dh))?;
            self.root_key = new_root2;
            self.previous_sending_counter = self.sending_counter;
            self.sending_counter = 0;
            self.sending_dh_sk = new_sending_sk;
            self.sending_dh_pk = new_sending_pk;
            self.sending_chain = Some(ChainKey(send_chain));
        }

        // 3. Skip ahead within the receiving chain if needed.
        self.skip_message_keys(msg.header.message_counter)?;

        // 4. Derive the message key for the requested counter.
        let chain = self
            .receiving_chain
            .as_ref()
            .ok_or(CryptoError::KeyDerivation)?;
        let (next_chain_key, msg_key) = kdf_ck(&chain.0)?;
        self.receiving_chain = Some(ChainKey(next_chain_key));
        self.receiving_counter += 1;

        decrypt_with_key(&msg_key, msg)
    }

    /// Derive and store message keys for counters [current, until) on the
    /// current receiving chain. This is what makes out-of-order delivery work.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if until < self.receiving_counter {
            return Ok(()); // nothing to skip
        }
        let to_skip = until - self.receiving_counter;
        if to_skip > MAX_SKIP_PER_STEP {
            return Err(CryptoError::KeyDerivation);
        }
        if self.skipped_keys.len() as u32 + to_skip > MAX_SKIPPED_MESSAGE_KEYS {
            return Err(CryptoError::KeyDerivation);
        }

        let Some(chain) = self.receiving_chain.as_ref() else {
            return Ok(());
        };
        let mut key = chain.0;
        let remote = match self.remote_dh_pk {
            Some(pk) => *pk.as_bytes(),
            None => return Ok(()),
        };

        for i in 0..to_skip {
            let (next_chain_key, msg_key) = kdf_ck(&key)?;
            self.skipped_keys
                .insert((remote, self.receiving_counter + i), msg_key);
            key = next_chain_key;
        }

        self.receiving_chain = Some(ChainKey(key));
        self.receiving_counter = until;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal KDFs
// ---------------------------------------------------------------------------

/// Root-key advancement: given the current root key and a fresh DH shared
/// secret, return (new_root, new_chain_key).
fn kdf_rk(
    root: &[u8; 32],
    dh_shared: &x25519_dalek::SharedSecret,
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_shared.as_bytes());
    let mut out = [0u8; 64];
    hk.expand(info::RATCHET_ROOT, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut new_root = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&out[..32]);
    new_chain.copy_from_slice(&out[32..]);
    Ok((new_root, new_chain))
}

/// Chain-key advancement: given the current chain key, return
/// (next_chain_key, message_key). Modelled after Signal's two HMAC-SHA256
/// calls but using HKDF with two distinct info strings.
fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);

    let mut next = [0u8; 32];
    hk.expand(info::RATCHET_NEXT_CHAIN, &mut next)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let mut msg = [0u8; 32];
    hk.expand(info::RATCHET_MSG_KEY, &mut msg)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok((next, msg))
}

fn counter_to_nonce(counter: u32) -> [u8; 12] {
    // Big-endian 12-byte nonce: first 8 bytes zero, last 4 bytes counter.
    // Safe because each message key is used exactly once (ratchet advance).
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn decrypt_with_key(key: &[u8; 32], msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
    let nonce = counter_to_nonce(msg.header.message_counter);
    let ad = msg.header.associated_data();
    aead::open(key, &nonce, &msg.ciphertext, &ad)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn shared_root() -> ([u8; 32], X25519Sk, X25519Pk) {
        let mut root = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut root);
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let bob_sk = X25519Sk::from(seed);
        let bob_pk = X25519Pk::from(&bob_sk);
        (root, bob_sk, bob_pk)
    }

    #[test]
    fn alice_sends_bob_decrypts() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        let msg = alice.encrypt(b"hello bob").unwrap();
        let plain = bob.decrypt(&msg).unwrap();
        assert_eq!(plain, b"hello bob");
    }

    #[test]
    fn bob_replies_alice_decrypts() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        let m1 = alice.encrypt(b"hi").unwrap();
        bob.decrypt(&m1).unwrap();

        let reply = bob.encrypt(b"hi back").unwrap();
        let plain = alice.decrypt(&reply).unwrap();
        assert_eq!(plain, b"hi back");
    }

    #[test]
    fn long_conversation_alternating() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        for i in 0..20 {
            let m = alice.encrypt(format!("A{i}").as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&m).unwrap(), format!("A{i}").as_bytes());

            let m = bob.encrypt(format!("B{i}").as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&m).unwrap(), format!("B{i}").as_bytes());
        }
    }

    #[test]
    fn burst_from_one_side_then_other() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        // Alice sends 5 without Bob replying.
        let mut bursts = vec![];
        for i in 0..5 {
            bursts.push(alice.encrypt(format!("A{i}").as_bytes()).unwrap());
        }
        for (i, m) in bursts.iter().enumerate() {
            assert_eq!(bob.decrypt(m).unwrap(), format!("A{i}").as_bytes());
        }

        // Now Bob sends 5 — this triggers his DH ratchet step on his first send.
        let mut bob_bursts = vec![];
        for i in 0..5 {
            bob_bursts.push(bob.encrypt(format!("B{i}").as_bytes()).unwrap());
        }
        for (i, m) in bob_bursts.iter().enumerate() {
            assert_eq!(alice.decrypt(m).unwrap(), format!("B{i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_within_chain() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        let m0 = alice.encrypt(b"zero").unwrap();
        let m1 = alice.encrypt(b"one").unwrap();
        let m2 = alice.encrypt(b"two").unwrap();

        // Bob receives them in scrambled order: 2, 0, 1.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        let mut m = alice.encrypt(b"authentic").unwrap();
        m.ciphertext[0] ^= 0x01;
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn tampered_header_rejected() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        let mut m = alice.encrypt(b"authentic").unwrap();
        m.header.message_counter = 999;
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn excessive_skip_is_rejected() {
        let (root, bob_sk, bob_pk) = shared_root();
        let mut alice = Session::alice_from_root(root, bob_pk).unwrap();
        let mut bob = Session::bob_from_root(root, bob_sk);

        // Forge a message claiming counter 1_000_000 (far past MAX_SKIP_PER_STEP).
        let mut m = alice.encrypt(b"x").unwrap();
        m.header.message_counter = 1_000_000;
        assert!(bob.decrypt(&m).is_err());
    }
}
