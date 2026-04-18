//! Integration test for the core wallet-style identity flow:
//!
//! 1. Generate a mnemonic (BIP39, 24 words)
//! 2. Derive the master seed
//! 3. Derive a full Identity (classical + PQ) from the seed
//! 4. Compute the fingerprint (address)
//! 5. Recover the identity from the mnemonic alone — all four keypairs and
//!    the fingerprint must match exactly.
//!
//! This is the "wallet recovery" story: the user who wrote down their 24
//! words can always reconstruct their full identity, forever.

use phantom_crypto::{Fingerprint, Identity, Seed};

#[test]
fn wallet_recovery_full_identity_matches() {
    // Step 1: generate mnemonic and original identity.
    let (seed_original, mnemonic) = Seed::generate();
    let id_original = Identity::from_seed(&seed_original).expect("derive identity");

    let ed_orig     = *id_original.ed25519_pk.as_bytes();
    let x_orig      = *id_original.x25519_pk.as_bytes();
    let mldsa_orig  = id_original.mldsa65_pk.as_bytes().to_vec();
    let mlkem_orig  = id_original.mlkem1024_pk.as_bytes().to_vec();
    let fp_orig     = id_original.fingerprint();

    // Step 2: simulate device loss. Only the mnemonic survives.
    let phrase = mnemonic.to_string();
    drop(id_original);
    drop(seed_original);

    // Step 3: recover from mnemonic alone.
    let parsed = Seed::parse_mnemonic(&phrase).expect("mnemonic parses");
    let seed_recovered = Seed::from_mnemonic(&parsed, "");
    let id_recovered = Identity::from_seed(&seed_recovered).expect("re-derive identity");

    // All four public keys must match byte-for-byte.
    assert_eq!(&ed_orig,            id_recovered.ed25519_pk.as_bytes());
    assert_eq!(&x_orig,             id_recovered.x25519_pk.as_bytes());
    assert_eq!(&mldsa_orig[..],     id_recovered.mldsa65_pk.as_bytes());
    assert_eq!(&mlkem_orig[..],     id_recovered.mlkem1024_pk.as_bytes());

    // And therefore so must the fingerprint — your address follows you.
    assert_eq!(fp_orig, id_recovered.fingerprint());
}

#[test]
fn wrong_passphrase_yields_different_identity() {
    let (_, mnemonic) = Seed::generate();
    let seed_a = Seed::from_mnemonic(&mnemonic, "");
    let seed_b = Seed::from_mnemonic(&mnemonic, "25th-word");

    let id_a = Identity::from_seed(&seed_a).unwrap();
    let id_b = Identity::from_seed(&seed_b).unwrap();

    assert_ne!(id_a.ed25519_pk.as_bytes(),     id_b.ed25519_pk.as_bytes());
    assert_ne!(id_a.x25519_pk.as_bytes(),      id_b.x25519_pk.as_bytes());
    assert_ne!(id_a.mldsa65_pk.as_bytes(),     id_b.mldsa65_pk.as_bytes());
    assert_ne!(id_a.mlkem1024_pk.as_bytes(),   id_b.mlkem1024_pk.as_bytes());
    assert_ne!(id_a.fingerprint(),             id_b.fingerprint());
}

#[test]
fn fingerprint_is_19_chars() {
    let (seed, _) = Seed::generate();
    let id = Identity::from_seed(&seed).unwrap();
    assert_eq!(id.fingerprint().display().len(), 19);
}

#[test]
fn fingerprint_parse_roundtrip() {
    let (seed, _) = Seed::generate();
    let id = Identity::from_seed(&seed).unwrap();
    let fp = id.fingerprint();
    let reparsed = Fingerprint::parse(&fp.display()).unwrap();
    assert_eq!(fp, reparsed);
}
