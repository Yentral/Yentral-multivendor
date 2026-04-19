//! Sealing and opening: SealedPayload ↔ Envelope(s) via a Session.
//!
//! ```text
//!   SealedPayload
//!        │
//!        ▼ bincode
//!   Vec<u8>
//!        │
//!        ▼ chunk into ≤ CHUNK_PAYLOAD_BYTES slices
//!   Vec<Frame>
//!        │
//!        ▼ Session::encrypt (ChaCha20-Poly1305)
//!   Vec<RatchetMessage>
//!        │
//!        ▼ serialise + random-pad to size bucket
//!   Vec<Envelope>
//! ```
//!
//! A `(len || bincode(RatchetMessage) || random_padding)` scheme keeps
//! padding simple and makes decoding unambiguous: the receiver reads the
//! first four bytes to discover how much of the bucket is real payload.

use phantom_crypto::{RatchetMessage, Session};
use phantom_wire::{Envelope, SizeBucket, DELIVERY_TOKEN_LEN};
use rand::{thread_rng, RngCore};
use thiserror::Error;

use crate::payload::{Frame, SealedPayload};

/// How many bytes of inner payload fit into one ciphertext chunk.
///
/// Upper bound: the ChunkBucket (64 KiB) minus ratchet/bincode overhead
/// (~100 B for header + length prefix + bincode framing). 48 KiB is a safe
/// round number that leaves plenty of slack and still produces ~1 chunk per
/// average mail body + attachment piece.
pub const CHUNK_PAYLOAD_BYTES: usize = 48 * 1024;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("encoding error: {0}")]
    Encode(String),

    #[error("payload exceeds max chunk count (65535)")]
    TooManyChunks,

    #[error("ratchet error: {0}")]
    Ratchet(#[from] phantom_crypto::CryptoError),

    #[error("envelope error: {0}")]
    Envelope(String),
}

// ---------------------------------------------------------------------------
// seal
// ---------------------------------------------------------------------------

/// Encrypt `payload` and produce one or more wire `Envelope`s.
///
/// - Small payloads produce a single envelope.
/// - Large payloads (e.g. files) are chunked into [`CHUNK_PAYLOAD_BYTES`]
///   slices; each slice goes through its own ratchet step and its own
///   envelope.
/// - Every envelope's ciphertext is random-padded to the smallest
///   [`SizeBucket`] that fits.
///
/// `timestamp_hour` is the current unix epoch seconds rounded down to
/// the hour — passed in so callers can control the clock.
pub fn seal(
    session: &mut Session,
    payload: &SealedPayload,
    timestamp_hour: u64,
) -> Result<Vec<Envelope>, SealError> {
    let serialised = bincode::serialize(payload).map_err(|e| SealError::Encode(e.to_string()))?;

    // Chunk into one or more Frames.
    let message_id = payload.id();
    let total_len = serialised.len();
    let chunks: Vec<&[u8]> = if total_len <= CHUNK_PAYLOAD_BYTES {
        vec![&serialised[..]]
    } else {
        serialised.chunks(CHUNK_PAYLOAD_BYTES).collect()
    };
    if chunks.len() > u16::MAX as usize {
        return Err(SealError::TooManyChunks);
    }
    let chunk_count = chunks.len() as u16;

    let mut envelopes = Vec::with_capacity(chunks.len());
    for (idx, chunk_bytes) in chunks.into_iter().enumerate() {
        let frame = Frame {
            message_id,
            chunk_index: idx as u16,
            chunk_count,
            chunk: chunk_bytes.to_vec(),
        };
        let frame_bytes =
            bincode::serialize(&frame).map_err(|e| SealError::Encode(e.to_string()))?;

        // Encrypt with the ratchet.
        let rm = session.encrypt(&frame_bytes)?;
        let rm_bytes = bincode::serialize(&rm).map_err(|e| SealError::Encode(e.to_string()))?;

        // Build the length-prefixed + padded payload.
        let inner_len = rm_bytes.len() as u32;
        let header_len = 4;
        let inner_total = header_len + rm_bytes.len();
        let bucket = SizeBucket::for_payload(inner_total).ok_or(SealError::Envelope(format!(
            "ratchet message too large ({inner_total} B) for any bucket",
        )))?;

        let mut padded = Vec::with_capacity(bucket.bytes());
        padded.extend_from_slice(&inner_len.to_be_bytes());
        padded.extend_from_slice(&rm_bytes);
        let pad_needed = bucket.bytes() - padded.len();
        padded.resize(bucket.bytes(), 0);
        thread_rng().fill_bytes(&mut padded[bucket.bytes() - pad_needed..]);

        // Derive a per-envelope delivery token. For Sprint 4 we use a
        // BLAKE3 hash over (message_id || chunk_index) as a placeholder; a
        // future sprint (P2P routing) will switch to a token bound to the
        // recipient's DHT identity.
        let delivery_token = delivery_token_for(&message_id, idx as u16);

        envelopes.push(Envelope {
            delivery_token,
            size_bucket: bucket,
            timestamp_hour,
            ciphertext: padded,
        });
    }

    Ok(envelopes)
}

// ---------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------

/// Result of opening one envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The payload was a single envelope: fully reconstructed.
    Complete(SealedPayload),

    /// This was one chunk of a larger payload. Pass it to the
    /// [`crate::Reassembler`] to accumulate the rest.
    Chunk(Frame),
}

/// Decrypt one incoming envelope and either return the full payload (for
/// single-envelope messages) or the underlying [`Frame`] for multi-chunk
/// reassembly.
pub fn open(session: &mut Session, envelope: &Envelope) -> Result<Opened, SealError> {
    envelope
        .validate()
        .map_err(|e| SealError::Envelope(e.to_string()))?;

    // Strip the length prefix + padding.
    if envelope.ciphertext.len() < 4 {
        return Err(SealError::Envelope("ciphertext too short".into()));
    }
    let inner_len = u32::from_be_bytes(envelope.ciphertext[..4].try_into().unwrap()) as usize;
    if 4 + inner_len > envelope.ciphertext.len() {
        return Err(SealError::Envelope("inner length exceeds bucket".into()));
    }
    let rm_bytes = &envelope.ciphertext[4..4 + inner_len];

    // Decode ratchet message.
    let rm: RatchetMessage =
        bincode::deserialize(rm_bytes).map_err(|e| SealError::Encode(e.to_string()))?;

    // Decrypt with the ratchet.
    let frame_bytes = session.decrypt(&rm)?;

    let frame: Frame =
        bincode::deserialize(&frame_bytes).map_err(|e| SealError::Encode(e.to_string()))?;

    // Single-chunk fast path.
    if frame.chunk_count == 1 && frame.chunk_index == 0 {
        let payload: SealedPayload =
            bincode::deserialize(&frame.chunk).map_err(|e| SealError::Encode(e.to_string()))?;
        return Ok(Opened::Complete(payload));
    }

    Ok(Opened::Chunk(frame))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn delivery_token_for(message_id: &[u8; 16], chunk_index: u16) -> [u8; DELIVERY_TOKEN_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"phantom/v1/delivery-token");
    h.update(message_id);
    h.update(&chunk_index.to_be_bytes());
    let out = h.finalize();
    let mut tok = [0u8; DELIVERY_TOKEN_LEN];
    tok.copy_from_slice(&out.as_bytes()[..DELIVERY_TOKEN_LEN]);
    tok
}
