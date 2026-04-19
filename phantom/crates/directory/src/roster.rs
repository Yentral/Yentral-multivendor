//! The roster: the whole directory, hybrid-signed by the org's CA.
//!
//! ```text
//!    ┌──────────────── signed by org CA ───────────────┐
//!    │                                                 │
//!    │   org_id  (16 B random)                         │
//!    │   version (u32, monotonically increasing)       │
//!    │   published_day (u32, unix-day)                 │
//!    │   members: [MemberEntry]                        │
//!    │                                                 │
//!    └─────────────────────────────────────────────────┘
//!                        │
//!                        ▼  same dual-signature pattern as PreKeyBundle
//!                ┌───────┴──────────┐
//!                ▼                  ▼
//!           Ed25519             ML-DSA-65
//!
//!    Consumer pins the CA's `IdentityPubs` (TOFU) and rejects any
//!    roster whose signatures don't verify against that exact pair.
//! ```

use ed25519_dalek::{
    Signature as EdSig, Signer as EdSigner, Verifier as EdVerifier, VerifyingKey as Ed25519Pk,
};
use phantom_crypto::{Identity, IdentityPubs};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entry::MemberEntry;

pub type OrgId = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterBody {
    pub org_id: OrgId,
    pub version: u32,
    pub published_day: u32,
    pub ca_identity: IdentityPubs,
    pub members: Vec<MemberEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterSignatures {
    pub ed25519: Vec<u8>,
    pub mldsa65: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgDirectory {
    pub body: RosterBody,
    pub signatures: RosterSignatures,
}

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error("crypto: {0}")]
    Crypto(#[from] phantom_crypto::CryptoError),

    #[error("bad signature")]
    BadSignature,

    #[error("encoding: {0}")]
    Encode(String),

    #[error("member not found: {0}")]
    MemberNotFound(String),

    #[error("CA fingerprint mismatch — pinned {pinned}, got {got}")]
    CaMismatch { pinned: String, got: String },
}

impl OrgDirectory {
    /// Build and hybrid-sign a fresh roster. Called by the org admin
    /// whenever members change.
    pub fn build(
        ca: &Identity,
        org_id: OrgId,
        version: u32,
        published_day: u32,
        members: Vec<MemberEntry>,
    ) -> Result<Self, DirectoryError> {
        let body = RosterBody {
            org_id,
            version,
            published_day,
            ca_identity: IdentityPubs::from_identity(ca),
            members,
        };
        let msg = canonical_body(&body)?;

        let ed_sig: EdSig = ca.ed25519_sk.sign(&msg);
        let mldsa_sig = phantom_crypto::pqc::MlDsa::sign(&ca.mldsa65_sk, &msg)?;

        Ok(Self {
            body,
            signatures: RosterSignatures {
                ed25519: ed_sig.to_bytes().to_vec(),
                mldsa65: mldsa_sig,
            },
        })
    }

    /// Verify the hybrid signatures against the CA identity embedded in
    /// the body. **You must separately check that the embedded CA matches
    /// your pinned CA** — this method only enforces self-consistency.
    pub fn verify(&self) -> Result<(), DirectoryError> {
        let ed_pk = Ed25519Pk::from_bytes(&self.body.ca_identity.ed25519)
            .map_err(|_| DirectoryError::BadSignature)?;
        let mldsa_pk =
            phantom_crypto::pqc::MlDsaPublicKey::from_bytes(&self.body.ca_identity.mldsa65)?;

        let msg = canonical_body(&self.body)?;
        let ed_sig = EdSig::from_slice(&self.signatures.ed25519)
            .map_err(|_| DirectoryError::BadSignature)?;
        ed_pk
            .verify(&msg, &ed_sig)
            .map_err(|_| DirectoryError::BadSignature)?;
        phantom_crypto::pqc::MlDsa::verify(&mldsa_pk, &msg, &self.signatures.mldsa65)
            .map_err(|_| DirectoryError::BadSignature)?;
        Ok(())
    }

    /// Full verification that includes a pinned-CA check. Use this in
    /// production — a plain `verify()` only guarantees the roster signed
    /// itself, not that the signer is the CA you trust.
    pub fn verify_against_pinned_ca(&self, pinned_ca: &IdentityPubs) -> Result<(), DirectoryError> {
        self.verify()?;
        if &self.body.ca_identity != pinned_ca {
            let pinned_fp = fingerprint_hex(&pinned_ca.ed25519);
            let got_fp = fingerprint_hex(&self.body.ca_identity.ed25519);
            return Err(DirectoryError::CaMismatch {
                pinned: pinned_fp,
                got: got_fp,
            });
        }
        Ok(())
    }

    /// Look up a member by display name.
    pub fn find_by_name(&self, name: &str) -> Option<&MemberEntry> {
        self.body.members.iter().find(|m| m.display_name == name)
    }

    /// Look up a member by Ed25519 pubkey (== the classical half of
    /// their identity).
    pub fn find_by_ed25519(&self, ed25519: &[u8; 32]) -> Option<&MemberEntry> {
        self.body
            .members
            .iter()
            .find(|m| &m.identity.ed25519 == ed25519)
    }

    /// Serialise to bytes for storage or transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DirectoryError> {
        bincode::serialize(self).map_err(|e| DirectoryError::Encode(e.to_string()))
    }

    /// Parse from bytes. **Does not verify** — call `verify*` explicitly.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DirectoryError> {
        bincode::deserialize(bytes).map_err(|e| DirectoryError::Encode(e.to_string()))
    }
}

fn canonical_body(body: &RosterBody) -> Result<Vec<u8>, DirectoryError> {
    let serialised = bincode::serialize(body).map_err(|e| DirectoryError::Encode(e.to_string()))?;
    let mut h = blake3::Hasher::new();
    h.update(b"phantom/v1/org-directory-sig");
    h.update(&serialised);
    Ok(h.finalize().as_bytes().to_vec())
}

fn fingerprint_hex(ed: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"phantom/v1/ca-fp");
    h.update(ed);
    hex::encode(&h.finalize().as_bytes()[..8])
}

// `hex` is not a workspace dep for this crate — inline a small encoder.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(LUT[(b >> 4) as usize] as char);
            s.push(LUT[(b & 0x0f) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::MemberRole;
    use phantom_crypto::{Identity, Seed};

    fn new_identity() -> Identity {
        let (seed, _) = Seed::generate();
        Identity::from_seed(&seed).unwrap()
    }

    fn sample_member(name: &str) -> MemberEntry {
        let id = new_identity();
        MemberEntry {
            display_name: name.to_string(),
            identity: IdentityPubs::from_identity(&id),
            department: Some("Engineering".into()),
            role: MemberRole::Member,
            added_on_day: 19830,
        }
    }

    #[test]
    fn build_and_verify() {
        let ca = new_identity();
        let members = vec![sample_member("Alice"), sample_member("Bob")];
        let dir = OrgDirectory::build(&ca, [9; 16], 1, 19830, members).unwrap();
        dir.verify().unwrap();
    }

    #[test]
    fn tampered_member_list_breaks_verification() {
        let ca = new_identity();
        let mut dir =
            OrgDirectory::build(&ca, [9; 16], 1, 19830, vec![sample_member("Alice")]).unwrap();
        dir.body.members[0].display_name = "Mallory".into();
        assert!(dir.verify().is_err());
    }

    #[test]
    fn wrong_ca_rejected_by_pinned_check() {
        let ca_real = new_identity();
        let ca_other = new_identity();
        let dir =
            OrgDirectory::build(&ca_real, [9; 16], 1, 19830, vec![sample_member("Alice")]).unwrap();

        // Self-consistent — verify() passes.
        dir.verify().unwrap();
        // But the consumer has pinned a different CA.
        let pinned_other = IdentityPubs::from_identity(&ca_other);
        assert!(dir.verify_against_pinned_ca(&pinned_other).is_err());

        // And the real pin works.
        let pinned_real = IdentityPubs::from_identity(&ca_real);
        dir.verify_against_pinned_ca(&pinned_real).unwrap();
    }

    #[test]
    fn find_lookups() {
        let ca = new_identity();
        let alice = sample_member("Alice");
        let bob = sample_member("Bob");
        let alice_ed = alice.identity.ed25519;
        let dir = OrgDirectory::build(&ca, [9; 16], 1, 19830, vec![alice, bob]).unwrap();

        assert!(dir.find_by_name("Alice").is_some());
        assert!(dir.find_by_name("Carol").is_none());
        assert!(dir.find_by_ed25519(&alice_ed).is_some());
    }

    #[test]
    fn serialise_roundtrip() {
        let ca = new_identity();
        let dir =
            OrgDirectory::build(&ca, [9; 16], 1, 19830, vec![sample_member("Alice")]).unwrap();
        let bytes = dir.to_bytes().unwrap();
        let restored = OrgDirectory::from_bytes(&bytes).unwrap();
        restored.verify().unwrap();
        assert_eq!(dir, restored);
    }
}
