//! Wire types for the request-response envelope-delivery protocol.

use phantom_wire::Envelope;
use serde::{Deserialize, Serialize};

/// Sent by a peer who wants an envelope delivered.
///
/// - `Direct` — deliver to the peer that accepts this request now.
///   The recipient's PHANTOM node stores it in its local inbox.
/// - `StoreForward` — the receiving node is a relay that should hold this
///   envelope on behalf of the ultimate recipient, identified by their
///   fingerprint. Any subsequent `FetchMailbox` call from that recipient
///   will retrieve it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeRequest {
    Direct {
        envelope: Envelope,
    },
    StoreForward {
        recipient_fingerprint: [u8; 8],
        envelope: Envelope,
    },
    FetchMailbox {
        recipient_fingerprint: [u8; 8],
    },
}

/// Reply to an [`EnvelopeRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeResponse {
    /// The envelope was accepted (into a local inbox or the relay's mailbox).
    Accepted,
    /// A fetch returned this batch (may be empty).
    Mailbox { envelopes: Vec<Envelope> },
    /// Peer declined — full mailbox, not acting as relay, or unknown recipient.
    Rejected { reason: String },
}

/// libp2p protocol name. Versioned via the "/v1" suffix so the wire format
/// can evolve without colliding on the wire.
pub const PHANTOM_ENVELOPE_PROTOCOL: &str = "/phantom/envelope/v1";
