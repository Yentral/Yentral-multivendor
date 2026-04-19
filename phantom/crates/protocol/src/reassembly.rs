//! Chunk reassembly for multi-envelope payloads (e.g. large file attachments).
//!
//! The sealing layer splits payloads larger than `CHUNK_PAYLOAD_BYTES` into
//! multiple envelopes tagged with a shared `message_id` and a
//! `chunk_index`/`chunk_count` pair. Envelopes can arrive out of order; the
//! `Reassembler` keeps per-`message_id` buckets and emits the complete
//! payload once every chunk has arrived.

use std::collections::HashMap;

use crate::payload::{Frame, MessageId, SealedPayload};

/// Per-session reassembly state. Drop it and in-flight multi-chunk messages
/// are lost — which is fine, because the ratchet state is also per-session.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<MessageId, PartialMessage>,
}

struct PartialMessage {
    chunk_count: u16,
    chunks: Vec<Option<Vec<u8>>>,
    bytes_held: usize,
}

/// Cap on how many un-finished multi-chunk messages a session can hold.
/// Prevents a peer from exhausting memory by starting many messages and
/// never completing them.
pub const MAX_PENDING_MESSAGES: usize = 64;

/// Cap on total unfinished bytes held across all pending messages. At
/// 48 KiB/chunk × 65535 chunks/message this is ~3 GiB max if uncapped,
/// which is nonsense for real use. 256 MiB is plenty for attachments.
pub const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ReassemblyError {
    #[error("chunk_count mismatch on message: had {had}, got {got}")]
    ChunkCountMismatch { had: u16, got: u16 },

    #[error("chunk_index {index} >= chunk_count {count}")]
    ChunkIndexOutOfRange { index: u16, count: u16 },

    #[error("too many pending partial messages")]
    TooManyPending,

    #[error("reassembly memory cap exceeded")]
    MemoryCapExceeded,

    #[error("decoding completed payload: {0}")]
    Decode(String),
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one chunk. Returns `Ok(Some(payload))` when the whole message
    /// has arrived, `Ok(None)` while chunks are still outstanding.
    pub fn push(&mut self, frame: Frame) -> Result<Option<SealedPayload>, ReassemblyError> {
        if frame.chunk_index >= frame.chunk_count {
            return Err(ReassemblyError::ChunkIndexOutOfRange {
                index: frame.chunk_index,
                count: frame.chunk_count,
            });
        }

        // Enforce pending-message cap before inserting.
        if !self.pending.contains_key(&frame.message_id)
            && self.pending.len() >= MAX_PENDING_MESSAGES
        {
            return Err(ReassemblyError::TooManyPending);
        }

        let total_after = self.total_bytes() + frame.chunk.len();
        if total_after > MAX_PENDING_BYTES {
            return Err(ReassemblyError::MemoryCapExceeded);
        }

        let pm = self
            .pending
            .entry(frame.message_id)
            .or_insert_with(|| PartialMessage {
                chunk_count: frame.chunk_count,
                chunks: vec![None; frame.chunk_count as usize],
                bytes_held: 0,
            });
        if pm.chunk_count != frame.chunk_count {
            return Err(ReassemblyError::ChunkCountMismatch {
                had: pm.chunk_count,
                got: frame.chunk_count,
            });
        }

        let idx = frame.chunk_index as usize;
        if pm.chunks[idx].is_none() {
            pm.bytes_held += frame.chunk.len();
            pm.chunks[idx] = Some(frame.chunk);
        }

        // Are all chunks in?
        if pm.chunks.iter().all(|c| c.is_some()) {
            let pm = self.pending.remove(&frame.message_id).unwrap();
            let total: usize = pm.chunks.iter().map(|c| c.as_ref().unwrap().len()).sum();
            let mut buf = Vec::with_capacity(total);
            for part in pm.chunks {
                buf.extend_from_slice(&part.unwrap());
            }
            let payload: SealedPayload =
                bincode::deserialize(&buf).map_err(|e| ReassemblyError::Decode(e.to_string()))?;
            return Ok(Some(payload));
        }

        Ok(None)
    }

    /// How many bytes of chunks are currently buffered across all pending
    /// messages. Mostly useful for diagnostics and testing.
    pub fn total_bytes(&self) -> usize {
        self.pending.values().map(|pm| pm.bytes_held).sum()
    }

    /// Number of in-flight multi-chunk messages.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
