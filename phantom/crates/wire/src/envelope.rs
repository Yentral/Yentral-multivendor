//! Unified message envelope.
//!
//! All PHANTOM messages — chat, mail, files, receipts — share one format.
//! An observer cannot tell from the envelope alone which kind of message
//! is inside; that distinction lives in the sealed payload.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DELIVERY_TOKEN_LEN: usize = 32;

/// Allowed wire sizes. Every ciphertext is padded to *exactly* one of these.
///
/// Using a small, fixed set of sizes defeats naive traffic analysis: a
/// watcher cannot distinguish a 40-byte "ok" from a 3 KiB paragraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SizeBucket {
    /// 1 KiB — short chat messages, receipts, presence.
    Small = 0,
    /// 4 KiB — typical chat / short mail.
    Medium = 1,
    /// 16 KiB — long mail, small attachments.
    Large = 2,
    /// 64 KiB — chunk size for large attachments; larger files split
    /// across multiple envelopes.
    Chunk = 3,
}

impl SizeBucket {
    pub const ALL: [SizeBucket; 4] = [
        SizeBucket::Small,
        SizeBucket::Medium,
        SizeBucket::Large,
        SizeBucket::Chunk,
    ];

    pub const fn bytes(self) -> usize {
        match self {
            SizeBucket::Small => 1024,
            SizeBucket::Medium => 4 * 1024,
            SizeBucket::Large => 16 * 1024,
            SizeBucket::Chunk => 64 * 1024,
        }
    }

    /// Smallest bucket that fits `payload_len` bytes, or `None` if the
    /// payload exceeds the largest bucket (caller must chunk).
    pub fn for_payload(payload_len: usize) -> Option<SizeBucket> {
        Self::ALL.into_iter().find(|b| b.bytes() >= payload_len)
    }
}

/// The kind of message inside the sealed payload. Never visible on the
/// wire — included here only as a structural reference for the payload
/// schema that the sealing layer (Sprint 4) will implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    Chat,
    Mail,
    File,
    Receipt,
    Presence,
}

/// What a relay node actually sees on the wire.
///
/// Both `delivery_token` and `ciphertext` are opaque blobs from the
/// relay's perspective. `size_bucket` is redundant with `ciphertext.len()`
/// but is transmitted explicitly so malformed traffic can be rejected
/// before allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub delivery_token: [u8; DELIVERY_TOKEN_LEN],
    pub size_bucket: SizeBucket,
    /// Unix seconds rounded down to the nearest hour.
    pub timestamp_hour: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error(
        "ciphertext length {got} does not match declared bucket {bucket:?} ({expected} bytes)"
    )]
    SizeMismatch {
        bucket: SizeBucket,
        expected: usize,
        got: usize,
    },

    #[error("serialisation error: {0}")]
    Codec(String),
}

impl Envelope {
    /// Validate that the declared bucket matches the ciphertext length.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        let expected = self.size_bucket.bytes();
        if self.ciphertext.len() != expected {
            return Err(EnvelopeError::SizeMismatch {
                bucket: self.size_bucket,
                expected,
                got: self.ciphertext.len(),
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        bincode::serialize(self).map_err(|e| EnvelopeError::Codec(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        bincode::deserialize(bytes).map_err(|e| EnvelopeError::Codec(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_for_payload_picks_smallest_fit() {
        assert_eq!(SizeBucket::for_payload(100), Some(SizeBucket::Small));
        assert_eq!(SizeBucket::for_payload(1024), Some(SizeBucket::Small));
        assert_eq!(SizeBucket::for_payload(1025), Some(SizeBucket::Medium));
        assert_eq!(SizeBucket::for_payload(4096), Some(SizeBucket::Medium));
        assert_eq!(SizeBucket::for_payload(16384), Some(SizeBucket::Large));
        assert_eq!(SizeBucket::for_payload(65536), Some(SizeBucket::Chunk));
        assert_eq!(SizeBucket::for_payload(65537), None);
    }

    #[test]
    fn validate_rejects_size_mismatch() {
        let env = Envelope {
            delivery_token: [0; DELIVERY_TOKEN_LEN],
            size_bucket: SizeBucket::Small,
            timestamp_hour: 0,
            ciphertext: vec![0u8; 512], // wrong: Small is 1024
        };
        assert!(env.validate().is_err());
    }

    #[test]
    fn validate_accepts_correct_bucket() {
        let env = Envelope {
            delivery_token: [0; DELIVERY_TOKEN_LEN],
            size_bucket: SizeBucket::Medium,
            timestamp_hour: 0,
            ciphertext: vec![0u8; SizeBucket::Medium.bytes()],
        };
        env.validate().unwrap();
    }

    #[test]
    fn encode_decode_roundtrip() {
        let env = Envelope {
            delivery_token: [7; DELIVERY_TOKEN_LEN],
            size_bucket: SizeBucket::Small,
            timestamp_hour: 1_700_000_000,
            ciphertext: vec![0xAB; SizeBucket::Small.bytes()],
        };
        let bytes = env.encode().unwrap();
        let back = Envelope::decode(&bytes).unwrap();
        assert_eq!(back.delivery_token, env.delivery_token);
        assert_eq!(back.size_bucket, env.size_bucket);
        assert_eq!(back.ciphertext.len(), env.ciphertext.len());
    }
}
