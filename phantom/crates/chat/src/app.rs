//! The core chat application. UI-agnostic: drives the P2P node, the
//! ratchet, the sealing layer, and the audit log.

use libp2p::{Multiaddr, PeerId};
use phantom_audit::{AuditEvent, AuditLog, EventKind};
use phantom_crypto::{
    initiate_session, Fingerprint, Identity, PreKeyBundle, PublishedBundle, Seed,
};
use phantom_p2p::{NodeError, PhantomNode};
use phantom_protocol::{new_message_id, open, seal, Opened, Reassembler, SealedPayload};
use phantom_wire::Envelope;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::contacts::{Contact, Contacts};

#[derive(Debug, Error)]
pub enum ChatError {
    #[error("crypto: {0}")]
    Crypto(#[from] phantom_crypto::CryptoError),

    #[error("node: {0}")]
    Node(#[from] NodeError),

    #[error("seal: {0}")]
    Seal(#[from] phantom_protocol::SealError),

    #[error("unknown contact: {0}")]
    UnknownContact(String),

    #[error("no session open with {0}; call open_session first")]
    NoSession(String),

    #[error("audit: {0}")]
    Audit(#[from] phantom_audit::AuditError),

    #[error("{0}")]
    Message(String),
}

/// High-level async chat application.
pub struct ChatApp {
    pub identity: Identity,
    pub node: PhantomNode,
    pub published: PublishedBundle,
    pub contacts: Mutex<Contacts>,
    pub audit: Mutex<AuditLog>,
    pub reassembler: Mutex<Reassembler>,
    audit_key: [u8; 32],
}

impl ChatApp {
    /// Bootstrap: generate a fresh wallet-style identity, spin up a P2P
    /// node, publish a first PreKey bundle. Returns the app handle and the
    /// BIP39 mnemonic phrase (space-separated words) that the caller MUST
    /// display to the user for backup.
    pub async fn bootstrap_new() -> Result<(Self, String), ChatError> {
        let (seed, mnemonic) = Seed::generate();
        let identity = Identity::from_seed(&seed)?;
        let app = Self::from_identity(identity, now_hour()).await?;
        Ok((app, mnemonic.to_string()))
    }

    /// Bootstrap from an existing mnemonic (recovery flow).
    pub async fn bootstrap_recover(phrase: &str, passphrase: &str) -> Result<Self, ChatError> {
        let mnemonic = Seed::parse_mnemonic(phrase)?;
        let seed = Seed::from_mnemonic(&mnemonic, passphrase);
        let identity = Identity::from_seed(&seed)?;
        Self::from_identity(identity, now_hour()).await
    }

    async fn from_identity(identity: Identity, now: u64) -> Result<Self, ChatError> {
        let node = PhantomNode::spawn(&identity).await?;
        let published = PreKeyBundle::build(&identity, 1, 1, now)?;
        published.public.verify()?;

        let audit_key = identity.storage_key.0;
        let mut audit = AuditLog::new();
        let actor = audit.hash_actor(identity.fingerprint().as_bytes());
        audit.append(
            &audit_key,
            &AuditEvent {
                timestamp_minute: now / 60,
                actor,
                kind: EventKind::IdentityCreated,
            },
        )?;

        Ok(Self {
            identity,
            node,
            published,
            contacts: Mutex::new(Contacts::new()),
            audit: Mutex::new(audit),
            reassembler: Mutex::new(Reassembler::new()),
            audit_key,
        })
    }

    /// Listen on a Multiaddr and return the actual bound address.
    pub async fn listen_on(&self, addr: Multiaddr) -> Result<Multiaddr, ChatError> {
        Ok(self.node.listen_on(addr).await?)
    }

    /// Dial an address so subsequent sends to that peer succeed.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), ChatError> {
        Ok(self.node.dial(addr).await?)
    }

    pub async fn local_peer_id(&self) -> Result<PeerId, ChatError> {
        Ok(self.node.local_peer_id().await?)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// Register or update a contact. No session is opened yet — call
    /// `open_session_as_initiator` or let the peer contact us first.
    pub async fn add_contact(
        &self,
        fingerprint: Fingerprint,
        display_name: String,
        peer_id: Option<PeerId>,
    ) {
        let mut contacts = self.contacts.lock().await;
        contacts.insert(Contact {
            fingerprint,
            display_name,
            peer_id,
            session: None,
        });
    }

    /// Alice-side: start a session with the given peer using their bundle.
    pub async fn open_session_as_initiator(
        &self,
        fp: Fingerprint,
        bundle: &PreKeyBundle,
        peer_id: PeerId,
    ) -> Result<(), ChatError> {
        let (session, initial) = initiate_session(&self.identity, bundle)?;
        let envelopes = seal_session_init(&initial)?;

        // Store the session.
        {
            let mut contacts = self.contacts.lock().await;
            let contact = contacts
                .get_mut(&fp)
                .ok_or_else(|| ChatError::UnknownContact(fp.display()))?;
            contact.session = Some(session);
            contact.peer_id = Some(peer_id);
        }

        // Publish the initial-message envelope over the wire.
        for env in envelopes {
            self.node.send_direct(peer_id, env).await?;
        }

        let actor = self.audit.lock().await.hash_actor(fp.as_bytes());
        self.log(EventKind::SessionEstablished { peer: actor })
            .await?;
        Ok(())
    }

    /// Send a chat message to an established contact.
    pub async fn send_chat(&self, fp: Fingerprint, body: &str) -> Result<(), ChatError> {
        let mut contacts = self.contacts.lock().await;
        let contact = contacts
            .get_mut(&fp)
            .ok_or_else(|| ChatError::UnknownContact(fp.display()))?;
        let session = contact
            .session
            .as_mut()
            .ok_or_else(|| ChatError::NoSession(fp.display()))?;
        let peer_id = contact
            .peer_id
            .ok_or_else(|| ChatError::NoSession(fp.display()))?;

        let payload = SealedPayload::Chat {
            id: new_message_id(),
            body: body.to_string(),
            reply_to: None,
        };
        let envelopes = seal(session, &payload, now_hour())?;
        let bytes_on_wire: u32 = envelopes.iter().map(|e| e.ciphertext.len() as u32).sum();

        // Release the contacts lock before awaiting network sends.
        drop(contacts);

        for env in envelopes {
            self.node.send_direct(peer_id, env).await?;
        }

        let actor = self.audit.lock().await.hash_actor(fp.as_bytes());
        self.log(EventKind::MessageSent {
            peer: actor,
            bytes_on_wire,
        })
        .await?;
        Ok(())
    }

    /// Poll once for an inbound envelope. If the envelope completes a
    /// SealedPayload, it is returned along with the sender's fingerprint.
    /// Otherwise the caller should poll again.
    pub async fn next_inbound(&self) -> Result<Option<(Fingerprint, SealedPayload)>, ChatError> {
        let Some(envelope) = self.node.next_envelope().await else {
            return Ok(None);
        };
        let bytes_on_wire = envelope.ciphertext.len() as u32;

        // Snapshot the list of known fingerprints so we don't hold the
        // contacts lock across `await` points inside the matching loop.
        let fingerprints: Vec<Fingerprint> = {
            let contacts = self.contacts.lock().await;
            contacts.list().map(|c| c.fingerprint).collect()
        };

        // Try each contact's session in turn. The ratchet fails fast on a
        // non-matching session, so this is cheap for reasonable-sized lists.
        for fp in fingerprints {
            let open_result = {
                let mut contacts = self.contacts.lock().await;
                let Some(contact) = contacts.get_mut(&fp) else {
                    continue;
                };
                let Some(session) = contact.session.as_mut() else {
                    continue;
                };
                open(session, &envelope).ok()
            };
            let Some(opened) = open_result else {
                continue;
            };

            let payload = match opened {
                Opened::Complete(p) => p,
                Opened::Chunk(frame) => {
                    let mut reassembler = self.reassembler.lock().await;
                    match reassembler.push(frame) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            self.log_peer_received(fp, bytes_on_wire).await?;
                            return Ok(None);
                        }
                        Err(e) => return Err(ChatError::Message(e.to_string())),
                    }
                }
            };
            self.log_peer_received(fp, bytes_on_wire).await?;
            return Ok(Some((fp, payload)));
        }

        // No session matched. In a full implementation this would trigger
        // parsing of a new-handshake initial message; Sprint 6 leaves that
        // to an explicit `accept_initiator` flow in the UI.
        Ok(None)
    }

    async fn log_peer_received(
        &self,
        peer_fp: Fingerprint,
        bytes_on_wire: u32,
    ) -> Result<(), ChatError> {
        let actor = self.audit.lock().await.hash_actor(peer_fp.as_bytes());
        self.log(EventKind::MessageReceived {
            peer: actor,
            bytes_on_wire,
        })
        .await
    }

    async fn log(&self, kind: EventKind) -> Result<(), ChatError> {
        let actor = self
            .audit
            .lock()
            .await
            .hash_actor(self.identity.fingerprint().as_bytes());
        let event = AuditEvent {
            timestamp_minute: now_hour() / 60,
            actor,
            kind,
        };
        self.audit.lock().await.append(&self.audit_key, &event)?;
        Ok(())
    }
}

fn now_hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600 * 3600)
        .unwrap_or(0)
}

/// Placeholder: PQ-X3DH+ initial-message delivery is its own protocol
/// (it carries the full hybrid pubs + ephemeral + KEM ciphertexts). For
/// Sprint 6 we piggy-back on the existing direct-send channel by wrapping
/// the InitialMessage into a one-shot Envelope. Future sprints promote
/// it to its own request_response variant.
fn seal_session_init(
    init: &phantom_crypto::InitialMessage,
) -> Result<Vec<phantom_wire::Envelope>, ChatError> {
    let bytes = bincode::serialize(init).map_err(|e| ChatError::Message(e.to_string()))?;
    let bucket = phantom_wire::SizeBucket::for_payload(4 + bytes.len()).ok_or_else(|| {
        ChatError::Message(format!("InitialMessage too large: {} B", bytes.len()))
    })?;
    let mut padded = Vec::with_capacity(bucket.bytes());
    padded.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    padded.extend_from_slice(&bytes);
    padded.resize(bucket.bytes(), 0);
    Ok(vec![Envelope {
        delivery_token: [0u8; 32],
        size_bucket: bucket,
        timestamp_hour: now_hour(),
        ciphertext: padded,
    }])
}
