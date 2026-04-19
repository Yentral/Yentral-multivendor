//! # PHANTOM Protocol — chat client core
//!
//! The `phantom-chat` crate exposes a reusable `ChatApp` that an outer
//! UI layer drives. The in-tree REPL binary (`phantom-chat`) is one such
//! driver; a GUI shell (Tauri, see `/desktop` directory one level up)
//! is another. Both wire the same core.
//!
//! The app owns:
//!
//! - The user's `Identity` and `Seed`
//! - A `PhantomNode` (libp2p)
//! - A per-peer `Session` ratchet state
//! - An `AuditLog` for local record-keeping
//! - A `Reassembler` for multi-chunk inbound payloads
//!
//! It provides high-level commands: open/accept session, send text,
//! receive, list contacts, rotate prekeys, etc.

pub mod app;
pub mod contacts;

pub use app::{ChatApp, ChatError};
pub use contacts::{Contact, Contacts};
