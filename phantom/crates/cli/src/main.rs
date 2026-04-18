//! `phantom` — developer CLI for identity and handshake inspection.
//!
//! ```text
//! phantom gen-identity                    # new mnemonic + identity
//! phantom show-id       --mnemonic "..."  # recover and display
//! phantom fingerprint   --mnemonic "..."  # just the address
//! phantom demo-handshake                  # run a full PQ-X3DH+ handshake
//! ```

use clap::{Parser, Subcommand};
use phantom_crypto::{initiate, respond, Identity, PreKeyBundle, Seed};

#[derive(Parser)]
#[command(
    name = "phantom",
    version,
    about = "PHANTOM Protocol — wallet-style identity tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh identity (24-word mnemonic + fingerprint).
    GenIdentity,

    /// Recover an identity from a mnemonic and show its details.
    ShowId {
        /// 24-word BIP39 mnemonic, space-separated, quoted.
        #[arg(long)]
        mnemonic: String,

        /// Optional passphrase (the "25th word").
        #[arg(long, default_value = "")]
        passphrase: String,
    },

    /// Print only the address (fingerprint) for a given mnemonic.
    Fingerprint {
        #[arg(long)]
        mnemonic: String,

        #[arg(long, default_value = "")]
        passphrase: String,
    },

    /// Run a full PQ-X3DH+ handshake between two freshly generated
    /// identities and show that both sides derive the same root key.
    /// Useful for sanity-checking the crypto locally.
    DemoHandshake,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::GenIdentity => cmd_gen_identity(),
        Command::ShowId {
            mnemonic,
            passphrase,
        } => cmd_show_id(&mnemonic, &passphrase),
        Command::Fingerprint {
            mnemonic,
            passphrase,
        } => cmd_fingerprint(&mnemonic, &passphrase),
        Command::DemoHandshake => cmd_demo_handshake(),
    }
}

fn cmd_gen_identity() {
    let (seed, mnemonic) = Seed::generate();
    let identity = match Identity::from_seed(&seed) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("failed to derive identity: {e}");
            std::process::exit(1);
        }
    };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║            PHANTOM IDENTITY GENERATED                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Jouw adres:");
    println!("  {}", identity.fingerprint());
    println!();
    println!("Zaadwoorden (SCHRIJF OP — zonder deze kun je je identiteit");
    println!("nooit meer herstellen):");
    println!();
    print_mnemonic_numbered(&mnemonic.to_string());
    println!();
    print_public_summary(&identity);
}

fn cmd_show_id(phrase: &str, passphrase: &str) {
    let mnemonic = match Seed::parse_mnemonic(phrase) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("invalid mnemonic: {e}");
            std::process::exit(1);
        }
    };
    let seed = Seed::from_mnemonic(&mnemonic, passphrase);
    let identity = match Identity::from_seed(&seed) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("failed to derive identity: {e}");
            std::process::exit(1);
        }
    };

    println!("Adres: {}", identity.fingerprint());
    println!();
    print_public_summary(&identity);
}

fn cmd_fingerprint(phrase: &str, passphrase: &str) {
    let mnemonic = match Seed::parse_mnemonic(phrase) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("invalid mnemonic: {e}");
            std::process::exit(1);
        }
    };
    let seed = Seed::from_mnemonic(&mnemonic, passphrase);
    let identity = match Identity::from_seed(&seed) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("failed to derive identity: {e}");
            std::process::exit(1);
        }
    };
    println!("{}", identity.fingerprint());
}

fn cmd_demo_handshake() {
    println!("▶ Genereer twee verse identiteiten (Alice + Bob)...");
    let (alice_seed, _) = Seed::generate();
    let (bob_seed, _) = Seed::generate();
    let alice = Identity::from_seed(&alice_seed).unwrap();
    let bob = Identity::from_seed(&bob_seed).unwrap();
    println!("  Alice: {}", alice.fingerprint());
    println!("  Bob:   {}", bob.fingerprint());
    println!();

    println!("▶ Bob publiceert een verse signed PreKey bundle (DHT simulatie)...");
    let now_hour = 1_700_000_000u64;
    let published = PreKeyBundle::build(&bob, 1, 100, now_hour).unwrap();
    println!(
        "  Bundle gesigneerd met Ed25519 ({} B) + ML-DSA-65 ({} B)",
        published.public.signatures.ed25519_sig.len(),
        published.public.signatures.mldsa65_sig.len()
    );
    published.public.verify().expect("verify");
    println!("  Hybride signature geverifieerd ✓");
    println!();

    println!("▶ Alice haalt de bundle op en start een PQ-X3DH+ handshake...");
    let out = initiate(&alice, &published.public).expect("initiate");
    println!("  4× X25519 DH + 2× ML-KEM encapsulation → HKDF-SHA256");
    println!("  Alice's root key:  {}", hex::encode(&out.root_key[..16]));
    println!();

    println!("▶ Bob ontvangt InitialMessage en reconstrueert de sleutel...");
    let bob_root = respond(
        &bob,
        &published.signed_prekey,
        &published.one_time_prekey,
        &out.initial_message,
    )
    .expect("respond");
    println!("  Bob's root key:    {}", hex::encode(&bob_root[..16]));
    println!();

    if out.root_key == bob_root {
        println!("✓ Beide zijden hebben dezelfde 32-byte root key afgeleid.");
        println!("  Zonder die sleutel ooit direct over te dragen.");
        println!("  Een aanvaller moet BEIDE X25519 én ML-KEM-1024 breken.");
    } else {
        eprintln!("✗ Root keys verschillen — dit zou niet moeten gebeuren.");
        std::process::exit(1);
    }
}

fn print_mnemonic_numbered(phrase: &str) {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    for (idx, chunk) in words.chunks(4).enumerate() {
        let base = idx * 4;
        for (offset, w) in chunk.iter().enumerate() {
            print!("  {:>2}. {:<10}", base + offset + 1, w);
        }
        println!();
    }
}

fn print_public_summary(id: &Identity) {
    let pub_id = id.public();
    println!("Publieke sleutels:");
    println!(
        "  Ed25519   ({} B):   {}",
        pub_id.ed25519.as_bytes().len(),
        hex::encode(&pub_id.ed25519.as_bytes()[..8])
    );
    println!(
        "  X25519    ({} B):   {}",
        pub_id.x25519.as_bytes().len(),
        hex::encode(&pub_id.x25519.as_bytes()[..8])
    );
    println!(
        "  ML-DSA-65 ({} B): {}",
        pub_id.mldsa65.as_bytes().len(),
        hex::encode(&pub_id.mldsa65.as_bytes()[..8])
    );
    println!(
        "  ML-KEM-1024 ({} B): {}",
        pub_id.mlkem1024.as_bytes().len(),
        hex::encode(&pub_id.mlkem1024.as_bytes()[..8])
    );
    println!();
    println!("Hybride crypto-stack:");
    println!("  signatures:      Ed25519 + ML-DSA-65  (FIPS 204)");
    println!("  key encapsulation: X25519 + ML-KEM-1024 (FIPS 203)");
}
