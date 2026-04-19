//! The composite libp2p `NetworkBehaviour` used by every PHANTOM node.
//!
//! Combines:
//!
//! - **Kademlia** — distributed hash table for prekey-bundle publication
//!   and organic peer routing.
//! - **request-response** (CBOR codec) — the envelope-delivery protocol.
//!
//! Zero-config local discovery via mDNS was initially considered but
//! dropped: multicast is unreliable across many internal network
//! topologies (and sandboxes refuse it outright). Production deployments
//! bootstrap by dialing a configured list of always-on relay peers that
//! are already in the DHT; from there Kademlia's own routing finds everyone
//! else.

use libp2p::{kad, request_response, swarm::NetworkBehaviour};

use crate::protocol::{EnvelopeRequest, EnvelopeResponse};

/// Composed behaviour; `#[derive(NetworkBehaviour)]` auto-generates the
/// `PhantomBehaviourEvent` enum and the plumbing that forwards events from
/// each sub-behaviour to the swarm.
#[derive(NetworkBehaviour)]
pub struct PhantomBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub request_response: request_response::cbor::Behaviour<EnvelopeRequest, EnvelopeResponse>,
}
