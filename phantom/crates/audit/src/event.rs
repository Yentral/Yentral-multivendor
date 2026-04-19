//! Audit event shape. Every variant carries only minimum-necessary data
//! to satisfy SOC 2 / ISO 27001 evidence requirements.

use serde::{Deserialize, Serialize};

/// BLAKE3-derived hash of an actor's fingerprint, keyed by the log's salt.
/// Cross-log correlation requires the salt — without it, two logs of the
/// same operator look unrelated.
pub type ActorHash = [u8; 16];

/// A single audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix-minute (seconds floored to the minute). Intentionally coarse.
    pub timestamp_minute: u64,
    pub actor: ActorHash,
    pub kind: EventKind,
}

/// What happened. Carefully limited set — new variants must justify their
/// evidentiary value (why an auditor needs this) against their privacy cost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// Operator unlocked their identity (mnemonic entered).
    IdentityUnlocked,

    /// Operator generated a brand-new identity.
    IdentityCreated,

    /// A signed prekey or one-time prekey bundle was rotated.
    PreKeyBundleRotated { signed_id: u32, one_time_id: u32 },

    /// A new session was established with a peer.
    SessionEstablished { peer: ActorHash },

    /// A message was sent. The BODY is never stored.
    MessageSent { peer: ActorHash, bytes_on_wire: u32 },

    /// A message was received.
    MessageReceived { peer: ActorHash, bytes_on_wire: u32 },

    /// A decryption failure occurred (authentication failure, tampered
    /// ciphertext, replay detection). Important for incident response.
    MessageRejected {
        peer: ActorHash,
        reason: RejectReason,
    },

    /// Administrator added a member to the org directory.
    DirectoryMemberAdded { new_member: ActorHash },

    /// Administrator removed a member from the org directory.
    DirectoryMemberRemoved { removed_member: ActorHash },

    /// The local device posture changed (e.g. OS patched, disk encryption
    /// toggled). Useful for Zero Trust re-evaluations.
    DevicePostureChange { posture_label: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    AeadMacFailure,
    UnknownSender,
    ReplayDetected,
    PreKeyExhausted,
    ProtocolVersionMismatch,
}
