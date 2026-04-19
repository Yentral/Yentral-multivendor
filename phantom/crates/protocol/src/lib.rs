//! # PHANTOM Protocol — unified sealing layer
//!
//! This crate is the glue between the Double Ratchet ([`phantom_crypto::Session`])
//! and the on-wire envelope format ([`phantom_wire::Envelope`]). It provides:
//!
//! - [`SealedPayload`] — a single enum covering every PHANTOM message type
//!   (chat, mail, file, receipt, presence). A relay node sees only a sealed
//!   envelope; the payload variant is recovered only by the recipient.
//! - [`seal`] — turns a `SealedPayload` into one or more `Envelope`s,
//!   chunking large payloads across multiple 64 KiB blocks and padding every
//!   ciphertext up to one of four fixed size buckets.
//! - [`open`] — inverse: given an incoming `Envelope`, decrypt via the
//!   ratchet, strip padding, and (if multi-chunk) feed the
//!   [`Reassembler`] until the full payload is available.
//!
//! ## Why chat, mail, files share one format
//!
//! A network observer must not be able to tell chat apart from mail apart
//! from a file upload. Same envelope shape, same size buckets, same timing
//! buckets. Only the recipient — who holds the ratchet state — can learn
//! which variant a given message carries.

pub mod payload;
pub mod reassembly;
pub mod sealing;

pub use payload::{new_message_id, Frame, MessageId, PresenceKind, SealedPayload};
pub use reassembly::{Reassembler, ReassemblyError};
pub use sealing::{open, seal, Opened, SealError, CHUNK_PAYLOAD_BYTES};
