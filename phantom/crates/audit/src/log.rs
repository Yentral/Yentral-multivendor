//! The audit log: hash-chained, individually-encrypted append-only entries.
//!
//! Layout in memory (what `append` and `read_all` operate on):
//!
//! ```text
//!   AuditLog {
//!       salt:    [u8; 16]      // used to hash actor fingerprints
//!       entries: Vec<SealedEntry>
//!   }
//!   SealedEntry {
//!       chain_hash: [u8; 32]   // BLAKE3(prev_chain_hash || ciphertext)
//!       nonce:      [u8; 12]
//!       ciphertext: Vec<u8>    // ChaCha20-Poly1305(event_bincode, ad=chain_hash)
//!   }
//! ```
//!
//! Mutation in the middle of the log breaks `chain_hash` from that point
//! forward. `verify()` walks the log start to end and catches any tampering.

use phantom_crypto::aead;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{ActorHash, AuditEvent};

pub const AUDIT_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
const ACTOR_HASH_LEN: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedEntry {
    pub chain_hash: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLog {
    pub salt: [u8; SALT_LEN],
    pub entries: Vec<SealedEntry>,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("encoding: {0}")]
    Encode(String),

    #[error("aead: {0}")]
    Aead(#[from] phantom_crypto::CryptoError),

    #[error("hash chain broken at entry {0}")]
    ChainBroken(usize),
}

impl AuditLog {
    /// Open a brand-new log with a fresh random salt.
    pub fn new() -> Self {
        let mut salt = [0u8; SALT_LEN];
        thread_rng().fill_bytes(&mut salt);
        Self {
            salt,
            entries: Vec::new(),
        }
    }

    /// Hash an actor fingerprint to an `ActorHash` using this log's salt.
    /// Different logs → different hashes for the same actor.
    pub fn hash_actor(&self, fingerprint: &[u8]) -> ActorHash {
        let mut h = blake3::Hasher::new();
        h.update(b"phantom/v1/audit-actor");
        h.update(&self.salt);
        h.update(fingerprint);
        let out = h.finalize();
        let mut a = [0u8; ACTOR_HASH_LEN];
        a.copy_from_slice(&out.as_bytes()[..ACTOR_HASH_LEN]);
        a
    }

    /// Append one event. The key is a 32-byte symmetric key (typically
    /// derived from the operator's `Identity::storage_key`).
    pub fn append(
        &mut self,
        audit_key: &[u8; AUDIT_KEY_LEN],
        event: &AuditEvent,
    ) -> Result<(), AuditError> {
        let plaintext = bincode::serialize(event).map_err(|e| AuditError::Encode(e.to_string()))?;

        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);

        let prev_chain = self
            .entries
            .last()
            .map(|e| e.chain_hash)
            .unwrap_or([0u8; 32]);
        let ciphertext = aead::seal(audit_key, &nonce, &plaintext, &prev_chain)?;

        // chain_hash = BLAKE3(prev_chain || ciphertext || nonce)
        let mut h = blake3::Hasher::new();
        h.update(b"phantom/v1/audit-chain");
        h.update(&prev_chain);
        h.update(&ciphertext);
        h.update(&nonce);
        let mut chain_hash = [0u8; 32];
        chain_hash.copy_from_slice(h.finalize().as_bytes());

        self.entries.push(SealedEntry {
            chain_hash,
            nonce,
            ciphertext,
        });
        Ok(())
    }

    /// Decrypt and return every event in order.
    pub fn read_all(&self, audit_key: &[u8; AUDIT_KEY_LEN]) -> Result<Vec<AuditEvent>, AuditError> {
        let mut out = Vec::with_capacity(self.entries.len());
        let mut prev_chain = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            // Re-check the chain hash first (catches middle-of-log tampering).
            let mut h = blake3::Hasher::new();
            h.update(b"phantom/v1/audit-chain");
            h.update(&prev_chain);
            h.update(&e.ciphertext);
            h.update(&e.nonce);
            let mut expected = [0u8; 32];
            expected.copy_from_slice(h.finalize().as_bytes());
            if expected != e.chain_hash {
                return Err(AuditError::ChainBroken(i));
            }

            let plaintext = aead::open(audit_key, &e.nonce, &e.ciphertext, &prev_chain)?;
            let event: AuditEvent =
                bincode::deserialize(&plaintext).map_err(|e| AuditError::Encode(e.to_string()))?;
            out.push(event);
            prev_chain = e.chain_hash;
        }
        Ok(out)
    }

    /// Number of entries currently in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize the whole log for on-disk storage (already encrypted).
    pub fn to_bytes(&self) -> Result<Vec<u8>, AuditError> {
        bincode::serialize(self).map_err(|e| AuditError::Encode(e.to_string()))
    }

    /// Deserialize a previously-saved log.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuditError> {
        bincode::deserialize(bytes).map_err(|e| AuditError::Encode(e.to_string()))
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, RejectReason};

    fn sample_event(minute: u64) -> AuditEvent {
        AuditEvent {
            timestamp_minute: minute,
            actor: [7u8; 16],
            kind: EventKind::IdentityUnlocked,
        }
    }

    #[test]
    fn roundtrip_single_event() {
        let key = [1u8; 32];
        let mut log = AuditLog::new();
        log.append(&key, &sample_event(100)).unwrap();
        let events = log.read_all(&key).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_minute, 100);
    }

    #[test]
    fn roundtrip_many_events() {
        let key = [2u8; 32];
        let mut log = AuditLog::new();
        for i in 0..50 {
            log.append(&key, &sample_event(i)).unwrap();
        }
        let events = log.read_all(&key).unwrap();
        assert_eq!(events.len(), 50);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev.timestamp_minute, i as u64);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let key = [1u8; 32];
        let wrong = [2u8; 32];
        let mut log = AuditLog::new();
        log.append(&key, &sample_event(0)).unwrap();
        assert!(log.read_all(&wrong).is_err());
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let key = [3u8; 32];
        let mut log = AuditLog::new();
        log.append(&key, &sample_event(0)).unwrap();
        log.append(&key, &sample_event(1)).unwrap();
        log.entries[0].ciphertext[0] ^= 0x01;
        assert!(log.read_all(&key).is_err());
    }

    #[test]
    fn middle_entry_tampering_breaks_chain() {
        let key = [4u8; 32];
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(&key, &sample_event(i)).unwrap();
        }
        // Flip a byte in entry 2's ciphertext.
        log.entries[2].ciphertext[1] ^= 0x01;
        let result = log.read_all(&key);
        assert!(matches!(result, Err(AuditError::ChainBroken(2))));
    }

    #[test]
    fn actor_hash_is_per_log() {
        let fp = [0xAAu8; 8];
        let log_a = AuditLog::new();
        let log_b = AuditLog::new();
        // Two logs with different salts must produce different hashes for the
        // same fingerprint — no cross-log correlation.
        assert_ne!(log_a.hash_actor(&fp), log_b.hash_actor(&fp));
        // Same log, same fingerprint → same hash.
        assert_eq!(log_a.hash_actor(&fp), log_a.hash_actor(&fp));
    }

    #[test]
    fn serialise_roundtrip() {
        let key = [5u8; 32];
        let mut log = AuditLog::new();
        log.append(&key, &sample_event(0)).unwrap();
        log.append(
            &key,
            &AuditEvent {
                timestamp_minute: 1,
                actor: [0; 16],
                kind: EventKind::MessageRejected {
                    peer: [0; 16],
                    reason: RejectReason::AeadMacFailure,
                },
            },
        )
        .unwrap();
        let bytes = log.to_bytes().unwrap();
        let restored = AuditLog::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 2);
        let events = restored.read_all(&key).unwrap();
        assert_eq!(events.len(), 2);
    }
}
