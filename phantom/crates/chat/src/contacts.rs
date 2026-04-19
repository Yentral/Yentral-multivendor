//! In-memory contact list.

use std::collections::HashMap;

use libp2p::PeerId;
use phantom_crypto::{Fingerprint, Session};

pub struct Contact {
    pub fingerprint: Fingerprint,
    pub display_name: String,
    pub peer_id: Option<PeerId>,
    pub session: Option<Session>,
}

#[derive(Default)]
pub struct Contacts {
    by_fp: HashMap<Fingerprint, Contact>,
}

impl Contacts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, contact: Contact) {
        self.by_fp.insert(contact.fingerprint, contact);
    }

    pub fn get(&self, fp: &Fingerprint) -> Option<&Contact> {
        self.by_fp.get(fp)
    }

    pub fn get_mut(&mut self, fp: &Fingerprint) -> Option<&mut Contact> {
        self.by_fp.get_mut(fp)
    }

    pub fn list(&self) -> impl Iterator<Item = &Contact> {
        self.by_fp.values()
    }

    pub fn len(&self) -> usize {
        self.by_fp.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_fp.is_empty()
    }
}
