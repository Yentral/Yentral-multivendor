//! The sealed payload — what lives *inside* an envelope's ciphertext.
//!
//! None of this is visible on the wire: relay nodes see only the envelope's
//! delivery token, size bucket, timestamp-hour, and the opaque ciphertext.

use serde::{Deserialize, Serialize};

/// A 16-byte random identifier for a logical message (may span multiple
/// envelope chunks). BLAKE3-derived at sealing time so a sender's counter
/// cannot leak via this field.
pub type MessageId = [u8; 16];

/// Every payload type PHANTOM transmits. All variants travel through the
/// same envelope format — the variant tag lives only *after* decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealedPayload {
    /// Short interactive message.
    Chat {
        id: MessageId,
        body: String,
        reply_to: Option<MessageId>,
    },

    /// Long-form email-style message with subject + thread linkage.
    Mail {
        id: MessageId,
        thread_id: [u8; 16],
        subject: String,
        body: String,
    },

    /// Binary file. `data` may be large — `seal()` will chunk across
    /// multiple envelopes as needed.
    File {
        id: MessageId,
        name: String,
        mime: String,
        data: Vec<u8>,
    },

    /// Delivery acknowledgement for a prior message.
    Receipt {
        id: MessageId,
        for_message: MessageId,
    },

    /// "User X is online / typing / away" — low-value, high-frequency.
    Presence { id: MessageId, kind: PresenceKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceKind {
    Online,
    Away,
    Typing,
}

impl SealedPayload {
    pub fn id(&self) -> MessageId {
        match self {
            SealedPayload::Chat { id, .. }
            | SealedPayload::Mail { id, .. }
            | SealedPayload::File { id, .. }
            | SealedPayload::Receipt { id, .. }
            | SealedPayload::Presence { id, .. } => *id,
        }
    }
}

/// Frame that wraps a (possibly chunked) sealed payload. One `Frame` fits
/// in the ciphertext of one [`phantom_wire::Envelope`]. Large payloads
/// produce multiple frames with a common `message_id`.
///
/// Wire ordering per chunk: length prefix + bincode(Frame) + random padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub message_id: MessageId,
    pub chunk_index: u16,
    pub chunk_count: u16,
    /// Raw bytes of the (possibly partial) serialised `SealedPayload`.
    pub chunk: Vec<u8>,
}

/// New unique random [`MessageId`] using the OS CSPRNG.
pub fn new_message_id() -> MessageId {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}
