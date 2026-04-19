//! # PHANTOM Protocol — P2P node
//!
//! Minimal libp2p-backed node that does two things:
//!
//! 1. Publishes and looks up [`phantom_crypto::PreKeyBundle`]s in a
//!    **Kademlia DHT**, keyed by the owner's fingerprint. This replaces
//!    Lavabit's DNS-based Signet with a pure-P2P directory.
//!
//! 2. Routes individual [`phantom_wire::Envelope`]s between peers over a
//!    **request-response** protocol. For offline recipients, any node on
//!    the network may opt to act as a *store-and-forward relay* that
//!    keeps envelopes in its in-memory mailbox until the recipient shows
//!    up (typical deployment: the always-on office desktops).
//!
//! ## What this crate deliberately does *not* do
//!
//! - No on-disk persistence of routed envelopes. Store-forward mailboxes
//!   are in-memory with a TTL — a crash just means some undelivered
//!   messages are lost, which the sender can re-send.
//! - No blockchain incentive layer for relay nodes. Internal deployments
//!   rely on a social contract (Sprint 7's org directory) rather than
//!   economic incentives. Public PHANTOM deployments would need one.
//! - No sophisticated routing. A peer either reaches another peer
//!   directly, or asks a relay to hold the envelope on the recipient's
//!   behalf. Graph-based routing is a later-sprint topic.
//!
//! ## Typical usage
//!
//! ```ignore
//! let node = PhantomNode::spawn(phantom_crypto::Identity::from_seed(&seed)?).await?;
//! node.publish_bundle(&published_bundle.public).await?;
//! let bundle = node.fetch_bundle(&fingerprint).await?;
//! node.send_envelope(&peer_id, &envelope).await?;
//! while let Some(inbound) = node.next_envelope().await {
//!     // route to local session
//! }
//! ```

pub mod behaviour;
pub mod mailbox;
pub mod node;
pub mod protocol;

pub use behaviour::{PhantomBehaviour, PhantomBehaviourEvent};
pub use mailbox::Mailbox;
pub use node::{NodeError, PhantomNode};
pub use protocol::{EnvelopeRequest, EnvelopeResponse};
