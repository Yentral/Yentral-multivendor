//! End-to-end: Alice and Bob perform PQ-X3DH+, hand the root key to the
//! Double Ratchet, and then exchange real encrypted messages in both
//! directions, including out-of-order delivery and tamper detection.

use phantom_crypto::{initiate_session, respond_session, Identity, PreKeyBundle, Seed};

fn new_identity() -> Identity {
    let (seed, _) = Seed::generate();
    Identity::from_seed(&seed).unwrap()
}

#[test]
fn full_conversation_after_pq_x3dh_plus() {
    let alice = new_identity();
    let bob = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();

    let (mut alice_session, initial) = initiate_session(&alice, &published.public).unwrap();
    let mut bob_session = respond_session(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &initial,
    )
    .unwrap();

    // Round 1: Alice → Bob
    let m1 = alice_session.encrypt(b"hello bob").unwrap();
    assert_eq!(bob_session.decrypt(&m1).unwrap(), b"hello bob");

    // Round 2: Bob → Alice (triggers his DH ratchet step on first send)
    let r1 = bob_session.encrypt(b"hello alice").unwrap();
    assert_eq!(alice_session.decrypt(&r1).unwrap(), b"hello alice");

    // Round 3-10: alternating chatter
    for i in 0..8 {
        let a_plain = format!("alice #{i}");
        let b_plain = format!("bob #{i}");

        let am = alice_session.encrypt(a_plain.as_bytes()).unwrap();
        assert_eq!(bob_session.decrypt(&am).unwrap(), a_plain.as_bytes());

        let bm = bob_session.encrypt(b_plain.as_bytes()).unwrap();
        assert_eq!(alice_session.decrypt(&bm).unwrap(), b_plain.as_bytes());
    }
}

#[test]
fn burst_and_reply_across_dh_ratchet() {
    let alice = new_identity();
    let bob = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let (mut alice_session, initial) = initiate_session(&alice, &published.public).unwrap();
    let mut bob_session = respond_session(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &initial,
    )
    .unwrap();

    // Alice sends 5 messages in a row — same sending chain.
    let mut alice_msgs = vec![];
    for i in 0..5 {
        alice_msgs.push(alice_session.encrypt(format!("A{i}").as_bytes()).unwrap());
    }
    for (i, m) in alice_msgs.iter().enumerate() {
        assert_eq!(bob_session.decrypt(m).unwrap(), format!("A{i}").as_bytes());
    }

    // Bob now sends 5 messages — triggers a DH ratchet step on Bob's side.
    let mut bob_msgs = vec![];
    for i in 0..5 {
        bob_msgs.push(bob_session.encrypt(format!("B{i}").as_bytes()).unwrap());
    }
    for (i, m) in bob_msgs.iter().enumerate() {
        assert_eq!(
            alice_session.decrypt(m).unwrap(),
            format!("B{i}").as_bytes()
        );
    }
}

#[test]
fn out_of_order_messages_still_decrypt() {
    let alice = new_identity();
    let bob = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let (mut alice_session, initial) = initiate_session(&alice, &published.public).unwrap();
    let mut bob_session = respond_session(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &initial,
    )
    .unwrap();

    let m0 = alice_session.encrypt(b"first").unwrap();
    let m1 = alice_session.encrypt(b"second").unwrap();
    let m2 = alice_session.encrypt(b"third").unwrap();

    // Network delivers them backwards.
    assert_eq!(bob_session.decrypt(&m2).unwrap(), b"third");
    assert_eq!(bob_session.decrypt(&m1).unwrap(), b"second");
    assert_eq!(bob_session.decrypt(&m0).unwrap(), b"first");
}

#[test]
fn tampered_session_message_rejected() {
    let alice = new_identity();
    let bob = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let (mut alice_session, initial) = initiate_session(&alice, &published.public).unwrap();
    let mut bob_session = respond_session(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &initial,
    )
    .unwrap();

    let mut m = alice_session.encrypt(b"authentic").unwrap();
    m.ciphertext[3] ^= 0x42;
    assert!(bob_session.decrypt(&m).is_err());
}

#[test]
fn messages_from_one_handshake_dont_decrypt_on_a_second() {
    // Alice and Bob run handshake A and exchange one message.
    // They then run a *fresh* handshake B (new ephemerals, new KEM randomness).
    // A message produced on session A must not decrypt on session B.
    let alice = new_identity();
    let bob = new_identity();

    let bundle_a = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let (mut a_session_a, init_a) = initiate_session(&alice, &bundle_a.public).unwrap();
    let _bob_session_a = respond_session(
        &bob,
        &bundle_a.signed_prekey,
        &bundle_a.one_time_prekey,
        &init_a,
    )
    .unwrap();

    // Second, independent handshake with different prekeys.
    let bundle_b = PreKeyBundle::build(&bob, 2, 43, 1_700_003_600).unwrap();
    let (_, init_b) = initiate_session(&alice, &bundle_b.public).unwrap();
    let mut bob_session_b = respond_session(
        &bob,
        &bundle_b.signed_prekey,
        &bundle_b.one_time_prekey,
        &init_b,
    )
    .unwrap();

    // A message from session A must NOT decrypt on Bob's session B.
    let m = a_session_a.encrypt(b"from session A").unwrap();
    assert!(bob_session_b.decrypt(&m).is_err());
}
