//! # PHANTOM Protocol — wire format
//!
//! The unified message envelope used for every transport: chat, mail,
//! files, receipts. The only thing a relay node sees is:
//!
//! 1. A **delivery token** — an opaque 32-byte blob that routes the
//!    message to the intended recipient without revealing who they are.
//! 2. A **ciphertext blob** — the sealed, padded, PQ-encrypted payload.
//! 3. A **size bucket** — one of {1 KiB, 4 KiB, 16 KiB, 64 KiB}. The
//!    ciphertext is always padded to exactly the bucket size.
//! 4. A **timestamp bucket** — unix seconds rounded down to the hour.
//!
//! Nothing else is visible. Sender identity lives inside the sealed
//! payload. Relay nodes have no way to correlate messages with users or
//! each other beyond the delivery token.
//!
//! Sprint-1 delivers only the type skeleton and size-bucket logic. The
//! actual sealing/unsealing routines land in Sprint-2 together with the
//! hybrid PQ-X3DH handshake.

pub mod envelope;

pub use envelope::{Envelope, MessageKind, SizeBucket};
