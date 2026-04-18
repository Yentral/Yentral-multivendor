//! Integration test: Alice initiates a PQ-X3DH+ session with Bob using
//! Bob's signed+verified PreKey bundle, and both sides derive the same
//! 32-byte root key without ever exchanging it directly.
//!
//! This proves the hybrid key-agreement works end-to-end: an attacker
//! would have to break both X25519 *and* ML-KEM-1024 to recover the key.

use phantom_crypto::{initiate, respond, Identity, PreKeyBundle, Seed};

fn new_identity() -> (Seed, Identity) {
    let (seed, _mnemonic) = Seed::generate();
    let id = Identity::from_seed(&seed).unwrap();
    (seed, id)
}

#[test]
fn alice_and_bob_derive_same_root_key() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    // Bob publishes a fresh bundle (and keeps the secret halves locally).
    let published =
        PreKeyBundle::build(&bob, /*spk_id*/ 1, /*otpk_id*/ 42, 1_700_000_000).unwrap();

    // Alice fetches the bundle and initiates.
    let out = initiate(&alice, &published.public).expect("initiate");

    // Bob receives the initial message and responds.
    let bob_root = respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message,
    )
    .expect("respond");

    // Both sides must have derived the same 32-byte root key.
    assert_eq!(out.root_key, bob_root);
}

#[test]
fn handshake_fails_if_bundle_signature_invalid() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    let mut published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    // Flip a byte in the Ed25519 signature.
    published.public.signatures.ed25519_sig[0] ^= 0x01;

    assert!(initiate(&alice, &published.public).is_err());
}

#[test]
fn handshake_fails_if_prekey_ids_mismatch() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let mut out = initiate(&alice, &published.public).expect("initiate");

    // Attacker rewrites which prekey IDs Alice used.
    out.initial_message.signed_prekey_id = 999;

    assert!(respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message
    )
    .is_err());
}

#[test]
fn handshake_fails_if_kem_ciphertext_tampered() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let mut out = initiate(&alice, &published.public).expect("initiate");
    // Flip a byte of the ML-KEM ciphertext to the one-time prekey.
    out.initial_message.mlkem_ct_otpk[0] ^= 0x01;

    let bob_root = respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message,
    )
    .expect("ML-KEM is IND-CCA2: decapsulation always returns *some* key");

    // ML-KEM is IND-CCA2 secure: a tampered ciphertext decapsulates to an
    // implicitly rejected pseudo-random value rather than failing outright.
    // That pseudo-random value will not equal Alice's shared secret, so the
    // derived root keys must differ.
    assert_ne!(out.root_key, bob_root);
}

#[test]
fn independent_sessions_produce_independent_keys() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    // Two back-to-back handshakes with different bundles.
    let bundle_a = PreKeyBundle::build(&bob, 1, 100, 1_700_000_000).unwrap();
    let bundle_b = PreKeyBundle::build(&bob, 2, 101, 1_700_003_600).unwrap();

    let a = initiate(&alice, &bundle_a.public).unwrap().root_key;
    let b = initiate(&alice, &bundle_b.public).unwrap().root_key;

    // Different ephemeral keys + different prekeys + KEM randomness → distinct.
    assert_ne!(a, b);
}

#[test]
fn substituted_sender_identity_yields_mismatched_key() {
    // Threat: Mallory sits between Alice and Bob. She captures Alice's
    // (public) IdentityPubs from the DHT and tries to impersonate Alice by
    // rewriting `sender_identity` in the initial message.
    //
    // The handshake does not explicitly authenticate `sender_identity` at
    // this layer — but the derived root key IMPLICITLY binds it, because
    // dh1 = DH(sender_ik_x, bob_spk_x). If Mallory substitutes an identity
    // whose X25519 secret she doesn't control, Bob's derived dh1 will not
    // match the one Alice originally computed.
    //
    // At the AEAD layer (Sprint 4) this manifests as a MAC failure on the
    // first payload. Here we observe it as a plain root-key mismatch.
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();
    let (_mallory_seed, mallory) = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let mut out = initiate(&alice, &published.public).expect("initiate");

    // Mallory replaces Alice's identity with her own.
    out.initial_message.sender_identity = phantom_crypto::IdentityPubs::from_identity(&mallory);

    let bob_root = respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message,
    )
    .expect("respond still succeeds: authentication is AEAD's job in Sprint 4");

    assert_ne!(
        out.root_key, bob_root,
        "implicit identity binding: mismatched IK_A must yield mismatched SK"
    );
}

#[test]
fn malformed_sender_identity_rejected() {
    // Regression guard: if Alice's claimed Ed25519 or ML-DSA pubkey is
    // outright malformed, Bob must reject the message before doing any
    // key-derivation work.
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let mut out = initiate(&alice, &published.public).expect("initiate");

    // Truncate the ML-DSA pubkey to something impossibly small.
    out.initial_message.sender_identity.mldsa65.truncate(10);

    assert!(respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message
    )
    .is_err());
}

#[test]
fn initial_message_serializes_and_roundtrips() {
    let (_bob_seed, bob) = new_identity();
    let (_alice_seed, alice) = new_identity();

    let published = PreKeyBundle::build(&bob, 1, 42, 1_700_000_000).unwrap();
    let out = initiate(&alice, &published.public).unwrap();

    let bytes = bincode::serialize(&out.initial_message).unwrap();
    let decoded: phantom_crypto::InitialMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(decoded, out.initial_message);
}
