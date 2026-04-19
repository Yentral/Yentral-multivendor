//! A single member entry in the directory.

use phantom_crypto::IdentityPubs;
use serde::{Deserialize, Serialize};

/// Role of a member. Drives Zero Trust access decisions downstream;
/// individual services map these to their own permission model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    /// Regular user with basic messaging rights.
    Member,
    /// Can issue new prekey bundles on behalf of offline users.
    Operator,
    /// Full administrative control — may add/remove members, rotate CA.
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    /// Human-readable label (display name or employee ID). Never used for
    /// cryptographic identity — that lives in `identity`.
    pub display_name: String,

    /// The member's long-term hybrid public identity — this is the "anchor"
    /// that subsequent PreKey bundles must match.
    pub identity: IdentityPubs,

    /// Optional department or team label.
    pub department: Option<String>,

    pub role: MemberRole,

    /// Unix-day when this member was added (admin-supplied).
    pub added_on_day: u32,
}
