//! The PHANTOM node — a libp2p Swarm driven by a dedicated Tokio task,
//! exposing an async API for publish/fetch/send/receive.
//!
//! Internally the swarm task runs a single `select!` loop that handles
//! both swarm events and control commands arriving on an mpsc channel.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    kad::{self, store::MemoryStore, Mode, Record, RecordKey},
    request_response::{self, ProtocolSupport, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use phantom_crypto::{Fingerprint, Identity, PreKeyBundle};
use phantom_wire::Envelope;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{
    behaviour::{PhantomBehaviour, PhantomBehaviourEvent},
    mailbox::Mailbox,
    protocol::{EnvelopeRequest, EnvelopeResponse, PHANTOM_ENVELOPE_PROTOCOL},
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("transport setup: {0}")]
    Transport(String),

    #[error("dht operation timed out")]
    Timeout,

    #[error("bundle not found in DHT")]
    BundleNotFound,

    #[error("encoding: {0}")]
    Encoding(String),

    #[error("channel closed — swarm task terminated")]
    ChannelClosed,

    #[error("swarm rejected: {0}")]
    Rejected(String),
}

// ---------------------------------------------------------------------------
// Commands — what the async API sends to the swarm task
// ---------------------------------------------------------------------------

enum Command {
    Listen {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<Multiaddr, NodeError>>,
    },
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    PublishBundle {
        fingerprint: Fingerprint,
        bundle_bytes: Vec<u8>,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    FetchBundle {
        fingerprint: Fingerprint,
        reply: oneshot::Sender<Result<PreKeyBundle, NodeError>>,
    },
    SendDirect {
        peer: PeerId,
        envelope: Envelope,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    LocalPeerId {
        reply: oneshot::Sender<PeerId>,
    },
}

// ---------------------------------------------------------------------------
// Handle — what the caller holds
// ---------------------------------------------------------------------------

/// Public handle to a running PHANTOM P2P node. `Clone` is cheap (it's just
/// a channel sender).
#[derive(Clone)]
pub struct PhantomNode {
    cmd_tx: mpsc::Sender<Command>,
    /// Channel of envelopes delivered to this node.
    inbox_rx: std::sync::Arc<tokio::sync::Mutex<mpsc::Receiver<Envelope>>>,
}

impl PhantomNode {
    /// Spawn a node bound to `identity`. Returns the handle immediately;
    /// the swarm runs on a dedicated Tokio task.
    pub async fn spawn(identity: &Identity) -> Result<Self, NodeError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (inbox_tx, inbox_rx) = mpsc::channel(256);

        let swarm = build_swarm(identity).map_err(|e| NodeError::Transport(e.to_string()))?;
        let local_peer = *swarm.local_peer_id();
        tracing::info!(%local_peer, "phantom node starting");

        tokio::spawn(swarm_task(swarm, cmd_rx, inbox_tx));

        Ok(Self {
            cmd_tx,
            inbox_rx: std::sync::Arc::new(tokio::sync::Mutex::new(inbox_rx)),
        })
    }

    pub async fn local_peer_id(&self) -> Result<PeerId, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::LocalPeerId { reply: tx })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)
    }

    pub async fn listen_on(&self, addr: Multiaddr) -> Result<Multiaddr, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Listen { addr, reply: tx })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Dial { addr, reply: tx })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Publish a signed prekey bundle to the Kademlia DHT under the owner's
    /// fingerprint. Assumes `bundle` has already been `.verify()`'d locally.
    pub async fn publish_bundle(&self, bundle: &PreKeyBundle) -> Result<(), NodeError> {
        let bytes = bincode::serialize(bundle).map_err(|e| NodeError::Encoding(e.to_string()))?;
        let fp = {
            let mut fp = [0u8; 8];
            // Derive fingerprint from the embedded identity pubs.
            let hasher_out = fingerprint_bytes(&bundle.body.identity);
            fp.copy_from_slice(&hasher_out);
            Fingerprint(fp)
        };
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::PublishBundle {
                fingerprint: fp,
                bundle_bytes: bytes,
                reply: tx,
            })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Look up another user's prekey bundle in the DHT by fingerprint.
    pub async fn fetch_bundle(&self, fp: &Fingerprint) -> Result<PreKeyBundle, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::FetchBundle {
                fingerprint: *fp,
                reply: tx,
            })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Send an envelope directly to a peer (they must be online).
    pub async fn send_direct(&self, peer: PeerId, envelope: Envelope) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SendDirect {
                peer,
                envelope,
                reply: tx,
            })
            .await
            .map_err(|_| NodeError::ChannelClosed)?;
        rx.await.map_err(|_| NodeError::ChannelClosed)?
    }

    /// Receive the next inbound envelope. Blocks until one arrives.
    pub async fn next_envelope(&self) -> Option<Envelope> {
        let mut rx = self.inbox_rx.lock().await;
        rx.recv().await
    }
}

// ---------------------------------------------------------------------------
// Swarm construction
// ---------------------------------------------------------------------------

fn build_swarm(
    _identity: &Identity,
) -> Result<Swarm<PhantomBehaviour>, Box<dyn std::error::Error>> {
    // We use a fresh libp2p keypair for transport identity. It's intentionally
    // separate from the PHANTOM wallet identity — the wallet identity's
    // Ed25519 key is NOT the same primitive libp2p wants to type-erase.
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mut kademlia = kad::Behaviour::new(
                key.public().to_peer_id(),
                MemoryStore::new(key.public().to_peer_id()),
            );
            kademlia.set_mode(Some(Mode::Server));
            let request_response =
                request_response::cbor::Behaviour::<EnvelopeRequest, EnvelopeResponse>::new(
                    std::iter::once((
                        libp2p::StreamProtocol::new(PHANTOM_ENVELOPE_PROTOCOL),
                        ProtocolSupport::Full,
                    )),
                    request_response::Config::default(),
                );
            PhantomBehaviour {
                kademlia,
                request_response,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();
    Ok(swarm)
}

// ---------------------------------------------------------------------------
// Swarm task
// ---------------------------------------------------------------------------

async fn swarm_task(
    mut swarm: Swarm<PhantomBehaviour>,
    mut cmd_rx: mpsc::Receiver<Command>,
    inbox_tx: mpsc::Sender<Envelope>,
) {
    let mut mailbox = Mailbox::new();
    // Outstanding DHT queries keyed by QueryId → oneshot channel to caller.
    let mut pending_get_bundle: std::collections::HashMap<
        kad::QueryId,
        oneshot::Sender<Result<PreKeyBundle, NodeError>>,
    > = std::collections::HashMap::new();
    let mut pending_put_bundle: std::collections::HashMap<
        kad::QueryId,
        oneshot::Sender<Result<(), NodeError>>,
    > = std::collections::HashMap::new();
    // Pending `listen_on` calls: resolved only once NewListenAddr fires,
    // since the caller asked for port 0 and needs the actual bound port.
    let mut pending_listens: std::collections::HashMap<
        libp2p::core::transport::ListenerId,
        oneshot::Sender<Result<Multiaddr, NodeError>>,
    > = std::collections::HashMap::new();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Command::LocalPeerId { reply }) => {
                    let _ = reply.send(*swarm.local_peer_id());
                }
                Some(Command::Listen { addr, reply }) => {
                    match swarm.listen_on(addr.clone()) {
                        Ok(listener_id) => { pending_listens.insert(listener_id, reply); }
                        Err(e) => { let _ = reply.send(Err(NodeError::Transport(e.to_string()))); }
                    }
                }
                Some(Command::Dial { addr, reply }) => {
                    match swarm.dial(addr) {
                        Ok(_) => { let _ = reply.send(Ok(())); }
                        Err(e) => { let _ = reply.send(Err(NodeError::Transport(e.to_string()))); }
                    }
                }
                Some(Command::PublishBundle { fingerprint, bundle_bytes, reply }) => {
                    let key = RecordKey::new(&dht_key_for_bundle(&fingerprint));
                    let record = Record::new(key, bundle_bytes);
                    match swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One) {
                        Ok(qid) => { pending_put_bundle.insert(qid, reply); }
                        Err(e) => { let _ = reply.send(Err(NodeError::Rejected(e.to_string()))); }
                    }
                }
                Some(Command::FetchBundle { fingerprint, reply }) => {
                    let key = RecordKey::new(&dht_key_for_bundle(&fingerprint));
                    let qid = swarm.behaviour_mut().kademlia.get_record(key);
                    pending_get_bundle.insert(qid, reply);
                }
                Some(Command::SendDirect { peer, envelope, reply }) => {
                    let _req_id = swarm.behaviour_mut().request_response.send_request(
                        &peer,
                        EnvelopeRequest::Direct { envelope },
                    );
                    // For Sprint 5 we ack send synchronously (fire-and-forget on
                    // the wire); a future sprint can track req_id → reply_on_success.
                    let _ = reply.send(Ok(()));
                }
                None => break,
            },

            event = swarm.select_next_some() => {
                handle_event(
                    event,
                    &mut mailbox,
                    &inbox_tx,
                    &mut swarm,
                    &mut pending_get_bundle,
                    &mut pending_put_bundle,
                    &mut pending_listens,
                ).await;
            }
        }
    }
}

async fn handle_event(
    event: SwarmEvent<PhantomBehaviourEvent>,
    mailbox: &mut Mailbox,
    inbox_tx: &mpsc::Sender<Envelope>,
    swarm: &mut Swarm<PhantomBehaviour>,
    pending_get: &mut std::collections::HashMap<
        kad::QueryId,
        oneshot::Sender<Result<PreKeyBundle, NodeError>>,
    >,
    pending_put: &mut std::collections::HashMap<
        kad::QueryId,
        oneshot::Sender<Result<(), NodeError>>,
    >,
    pending_listens: &mut std::collections::HashMap<
        libp2p::core::transport::ListenerId,
        oneshot::Sender<Result<Multiaddr, NodeError>>,
    >,
) {
    match event {
        SwarmEvent::NewListenAddr {
            listener_id,
            address,
        } => {
            tracing::info!(%address, "listening");
            if let Some(reply) = pending_listens.remove(&listener_id) {
                let _ = reply.send(Ok(address));
            }
        }
        SwarmEvent::Behaviour(PhantomBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed { id, result, .. },
        )) => match result {
            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(kad::PeerRecord {
                record,
                ..
            }))) => {
                if let Some(reply) = pending_get.remove(&id) {
                    match bincode::deserialize::<PreKeyBundle>(&record.value) {
                        Ok(bundle) => {
                            let _ = reply.send(Ok(bundle));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(NodeError::Encoding(e.to_string())));
                        }
                    }
                }
            }
            kad::QueryResult::GetRecord(Err(_)) => {
                if let Some(reply) = pending_get.remove(&id) {
                    let _ = reply.send(Err(NodeError::BundleNotFound));
                }
            }
            kad::QueryResult::PutRecord(Ok(_)) => {
                if let Some(reply) = pending_put.remove(&id) {
                    let _ = reply.send(Ok(()));
                }
            }
            kad::QueryResult::PutRecord(Err(e)) => {
                if let Some(reply) = pending_put.remove(&id) {
                    let _ = reply.send(Err(NodeError::Rejected(e.to_string())));
                }
            }
            _ => {}
        },
        SwarmEvent::Behaviour(PhantomBehaviourEvent::RequestResponse(
            request_response::Event::Message { message, .. },
        )) => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                handle_envelope_request(request, channel, mailbox, inbox_tx, swarm).await;
            }
            request_response::Message::Response { .. } => {
                // We use fire-and-forget in Sprint 5. Responses from relays
                // could be surfaced via a separate channel in a later sprint.
            }
        },
        _ => {}
    }
}

async fn handle_envelope_request(
    request: EnvelopeRequest,
    channel: ResponseChannel<EnvelopeResponse>,
    mailbox: &mut Mailbox,
    inbox_tx: &mpsc::Sender<Envelope>,
    swarm: &mut Swarm<PhantomBehaviour>,
) {
    let response = match request {
        EnvelopeRequest::Direct { envelope } => {
            let _ = inbox_tx.send(envelope).await;
            EnvelopeResponse::Accepted
        }
        EnvelopeRequest::StoreForward {
            recipient_fingerprint,
            envelope,
        } => {
            if mailbox.store(recipient_fingerprint, envelope) {
                EnvelopeResponse::Accepted
            } else {
                EnvelopeResponse::Rejected {
                    reason: "mailbox full".into(),
                }
            }
        }
        EnvelopeRequest::FetchMailbox {
            recipient_fingerprint,
        } => {
            let envelopes = mailbox.drain(&recipient_fingerprint);
            EnvelopeResponse::Mailbox { envelopes }
        }
    };
    let _ = swarm
        .behaviour_mut()
        .request_response
        .send_response(channel, response);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dht_key_for_bundle(fp: &Fingerprint) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"phantom/v1/dht-bundle-key");
    h.update(fp.as_bytes());
    h.finalize().as_bytes().to_vec()
}

fn fingerprint_bytes(pubs: &phantom_crypto::IdentityPubs) -> [u8; 8] {
    let mut h = blake3::Hasher::new();
    h.update(b"phantom/v1/fingerprint");
    h.update(&pubs.ed25519);
    h.update(&pubs.x25519);
    h.update(&pubs.mldsa65);
    h.update(&pubs.mlkem1024);
    let out = h.finalize();
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&out.as_bytes()[..8]);
    fp
}
