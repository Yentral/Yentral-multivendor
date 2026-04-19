//! In-memory store-and-forward mailbox.
//!
//! A relay node holds envelopes for offline recipients, keyed by their
//! 8-byte fingerprint. Bounded in both entries and bytes to prevent DoS
//! via flooding with garbage envelopes.

use std::collections::HashMap;

use phantom_wire::Envelope;

pub const MAX_ENVELOPES_PER_RECIPIENT: usize = 256;
pub const MAX_TOTAL_ENVELOPES: usize = 16 * 1024;

#[derive(Default)]
pub struct Mailbox {
    inner: HashMap<[u8; 8], Vec<Envelope>>,
    total: usize,
}

impl Mailbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an envelope for `recipient`. Returns `false` if the caps were
    /// hit (caller should tell the peer "rejected: mailbox full").
    pub fn store(&mut self, recipient: [u8; 8], envelope: Envelope) -> bool {
        if self.total >= MAX_TOTAL_ENVELOPES {
            return false;
        }
        let slot = self.inner.entry(recipient).or_default();
        if slot.len() >= MAX_ENVELOPES_PER_RECIPIENT {
            return false;
        }
        slot.push(envelope);
        self.total += 1;
        true
    }

    /// Drain all envelopes for `recipient`, returning them in insertion
    /// order. The mailbox slot is emptied atomically.
    pub fn drain(&mut self, recipient: &[u8; 8]) -> Vec<Envelope> {
        let got = self.inner.remove(recipient).unwrap_or_default();
        self.total -= got.len();
        got
    }

    pub fn total_envelopes(&self) -> usize {
        self.total
    }

    pub fn recipient_count(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_wire::{SizeBucket, DELIVERY_TOKEN_LEN};

    fn dummy_envelope() -> Envelope {
        Envelope {
            delivery_token: [0; DELIVERY_TOKEN_LEN],
            size_bucket: SizeBucket::Small,
            timestamp_hour: 0,
            ciphertext: vec![0u8; SizeBucket::Small.bytes()],
        }
    }

    #[test]
    fn store_and_drain_roundtrip() {
        let mut mb = Mailbox::new();
        assert!(mb.store([1; 8], dummy_envelope()));
        assert!(mb.store([1; 8], dummy_envelope()));
        assert!(mb.store([2; 8], dummy_envelope()));
        assert_eq!(mb.total_envelopes(), 3);
        assert_eq!(mb.recipient_count(), 2);

        let got = mb.drain(&[1; 8]);
        assert_eq!(got.len(), 2);
        assert_eq!(mb.total_envelopes(), 1);
        assert_eq!(mb.recipient_count(), 1);
    }

    #[test]
    fn drain_empty_returns_empty_vec() {
        let mut mb = Mailbox::new();
        assert_eq!(mb.drain(&[0; 8]).len(), 0);
    }

    #[test]
    fn per_recipient_cap_enforced() {
        let mut mb = Mailbox::new();
        for _ in 0..MAX_ENVELOPES_PER_RECIPIENT {
            assert!(mb.store([3; 8], dummy_envelope()));
        }
        // Next one refused.
        assert!(!mb.store([3; 8], dummy_envelope()));
        // Different recipient still allowed.
        assert!(mb.store([4; 8], dummy_envelope()));
    }
}
