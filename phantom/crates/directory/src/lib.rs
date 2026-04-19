//! # PHANTOM Protocol — signed organisational directory
//!
//! For **internal deployments** of PHANTOM (the primary use case), every
//! user is a member of one or more organisations. An `OrgDirectory` is a
//! signed roster that tells a newly-joined member which fingerprints
//! belong to which real colleagues.
//!
//! The directory is itself a PHANTOM object, signed by the organisation's
//! CA keypair (just another `Identity` held by the admin). It is published
//! out-of-band — QR code at onboarding, shared link, or via an internal
//! DHT once Sprint 5 is wired up.
//!
//! ## Threat model
//!
//! Without the directory signature, Mallory (a colleague) could forge
//! `Alice's fingerprint = X1X2-...` and trick Bob. With it, Bob's
//! PHANTOM client refuses to trust any fingerprint whose entry is not
//! signed by the org CA.
//!
//! The CA's own identity is distributed TOFU — first contact prints the
//! CA fingerprint on paper; thereafter the client pins it.

pub mod entry;
pub mod roster;

pub use entry::{MemberEntry, MemberRole};
pub use roster::{DirectoryError, OrgDirectory, OrgId};
