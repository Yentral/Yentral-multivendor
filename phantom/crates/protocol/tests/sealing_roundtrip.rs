//! End-to-end: Alice seals a payload through her Session, produces one or
//! more Envelopes, and Bob opens them through his Session. Includes chunked
//! file transfers, out-of-order chunk delivery, and tamper detection.

use phantom_crypto::{initiate_session, respond_session, Identity, PreKeyBundle, Seed};
use phantom_protocol::{
    new_message_id, open, seal, Opened, PresenceKind, Reassembler, SealedPayload,
};

fn identity() -> Identity {
    let (seed, _) = Seed::generate();
    Identity::from_seed(&seed).unwrap()
}

fn new_sessions() -> (phantom_crypto::Session, phantom_crypto::Session) {
    let alice = identity();
    let bob = identity();
    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let (alice_session, initial) = initiate_session(&alice, &published.public).unwrap();
    let bob_session = respond_session(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &initial,
    )
    .unwrap();
    (alice_session, bob_session)
}

#[test]
fn chat_message_single_envelope_roundtrip() {
    let (mut alice, mut bob) = new_sessions();

    let payload = SealedPayload::Chat {
        id: new_message_id(),
        body: "Hoi Bob!".into(),
        reply_to: None,
    };
    let envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    assert_eq!(envs.len(), 1, "short chat fits in one envelope");

    match open(&mut bob, &envs[0]).unwrap() {
        Opened::Complete(p) => assert_eq!(p, payload),
        Opened::Chunk(_) => panic!("single-envelope chat should be Complete"),
    }
}

#[test]
fn mail_message_bucket_padded() {
    let (mut alice, mut bob) = new_sessions();

    let payload = SealedPayload::Mail {
        id: new_message_id(),
        thread_id: [0xAB; 16],
        subject: "Vergadering morgen".into(),
        body: "Kom je om 10:00? Groet, Alice.".repeat(40),
    };
    let envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    assert_eq!(envs.len(), 1);
    envs[0].validate().expect("envelope self-consistent");

    match open(&mut bob, &envs[0]).unwrap() {
        Opened::Complete(p) => assert_eq!(p, payload),
        Opened::Chunk(_) => panic!("should be single-envelope"),
    }
}

#[test]
fn receipt_presence_roundtrip() {
    let (mut alice, mut bob) = new_sessions();
    let target = new_message_id();

    let receipt = SealedPayload::Receipt {
        id: new_message_id(),
        for_message: target,
    };
    let envs = seal(&mut alice, &receipt, 1_700_000_000).unwrap();
    let Opened::Complete(p) = open(&mut bob, &envs[0]).unwrap() else {
        panic!("receipt must be single-envelope")
    };
    assert_eq!(p, receipt);

    let presence = SealedPayload::Presence {
        id: new_message_id(),
        kind: PresenceKind::Typing,
    };
    let envs = seal(&mut alice, &presence, 1_700_000_000).unwrap();
    let Opened::Complete(p) = open(&mut bob, &envs[0]).unwrap() else {
        panic!("presence must be single-envelope")
    };
    assert_eq!(p, presence);
}

#[test]
fn large_file_chunked_roundtrip() {
    let (mut alice, mut bob) = new_sessions();

    // 200 KiB file → expect 5 chunks (48 KiB each).
    let data = vec![0xCDu8; 200 * 1024];
    let payload = SealedPayload::File {
        id: new_message_id(),
        name: "document.pdf".into(),
        mime: "application/pdf".into(),
        data: data.clone(),
    };
    let envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    assert!(
        envs.len() >= 5,
        "expected ≥5 chunks for 200 KiB, got {}",
        envs.len()
    );

    let mut reassembler = Reassembler::new();
    let mut completed = None;
    for env in &envs {
        match open(&mut bob, env).unwrap() {
            Opened::Complete(_) => panic!("multi-chunk should not return Complete"),
            Opened::Chunk(frame) => {
                if let Some(p) = reassembler.push(frame).unwrap() {
                    completed = Some(p);
                }
            }
        }
    }

    let p = completed.expect("reassembly completes after last chunk");
    assert_eq!(p, payload);
    assert_eq!(
        reassembler.pending_count(),
        0,
        "no pending after completion"
    );
}

#[test]
fn large_file_chunks_can_arrive_in_any_order() {
    let (mut alice, mut bob) = new_sessions();

    let data = vec![0x11u8; 150 * 1024];
    let payload = SealedPayload::File {
        id: new_message_id(),
        name: "photo.jpg".into(),
        mime: "image/jpeg".into(),
        data: data.clone(),
    };
    let envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    assert!(envs.len() >= 3);

    // Reverse the delivery order. The ratchet supports out-of-order messages,
    // so decryption still works; reassembly must also handle shuffled chunks.
    let mut reversed = envs.clone();
    reversed.reverse();

    let mut reassembler = Reassembler::new();
    let mut completed = None;
    for env in &reversed {
        match open(&mut bob, env).unwrap() {
            Opened::Complete(_) => panic!("multi-chunk should not return Complete"),
            Opened::Chunk(frame) => {
                if let Some(p) = reassembler.push(frame).unwrap() {
                    completed = Some(p);
                }
            }
        }
    }
    assert_eq!(completed.unwrap(), payload);
}

#[test]
fn tampered_envelope_rejected() {
    let (mut alice, mut bob) = new_sessions();
    let payload = SealedPayload::Chat {
        id: new_message_id(),
        body: "authentic".into(),
        reply_to: None,
    };
    let mut envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    // Flip a byte inside the ciphertext — AEAD MAC must fail.
    envs[0].ciphertext[100] ^= 0x01;

    assert!(open(&mut bob, &envs[0]).is_err());
}

#[test]
fn envelope_sizes_are_in_the_bucket_set() {
    let (mut alice, _bob) = new_sessions();
    let payload = SealedPayload::Chat {
        id: new_message_id(),
        body: "x".into(),
        reply_to: None,
    };
    let envs = seal(&mut alice, &payload, 1_700_000_000).unwrap();
    let allowed = [1024, 4096, 16384, 65536];
    assert!(allowed.contains(&envs[0].ciphertext.len()));
}
