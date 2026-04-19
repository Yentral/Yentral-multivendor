//! # PHANTOM Protocol — encrypted audit log
//!
//! Append-only record of security-relevant events for ISO 27001 / SOC 2
//! evidence. Every entry is ChaCha20-Poly1305 sealed under a per-log
//! "audit key" derived from the operator's identity storage key, so:
//!
//! - The log is **readable** only by someone who has the audit key
//!   (intentional — auditor is granted the key out-of-band).
//! - The log is **unforgeable** in the sense that each entry is
//!   MAC-protected individually AND hash-chained to its predecessor:
//!   any mutation in the middle breaks the chain from that point on.
//! - The log is **append-only**: there is no remove API.
//!
//! ## What PHANTOM *does not* log in plaintext
//!
//! - No message bodies. Ever.
//! - Actor identities are BLAKE3-hashed with a per-log salt, not stored
//!   as fingerprints. Cross-log correlation is impossible without the salt.
//! - Timestamps are rounded down to the minute.
//!
//! ## What it does log
//!
//! See [`EventKind`]. Login, key rotation, message send/receive counts,
//! administrative changes — anything you need to demonstrate compliance
//! without betraying content.

pub mod event;
pub mod log;

pub use event::{ActorHash, AuditEvent, EventKind};
pub use log::{AuditError, AuditLog};
