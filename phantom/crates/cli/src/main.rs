//! `phantom` — Sprint-1 CLI for identity generation and inspection.
//!
//! ```text
//! phantom gen-identity               # new mnemonic + identity
//! phantom show-id --mnemonic "..."   # recover and display
//! phantom fingerprint --mnemonic "..." # just the address
//! ```

use clap::{Parser, Subcommand};
use phantom_crypto::{Identity, Seed};

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
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::GenIdentity                     => cmd_gen_identity(),
        Command::ShowId     { mnemonic, passphrase } => cmd_show_id(&mnemonic, &passphrase),
        Command::Fingerprint { mnemonic, passphrase } => cmd_fingerprint(&mnemonic, &passphrase),
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
    println!("  Ed25519   ({} B):   {}",
        pub_id.ed25519.as_bytes().len(),
        hex::encode(&pub_id.ed25519.as_bytes()[..8]));
    println!("  X25519    ({} B):   {}",
        pub_id.x25519.as_bytes().len(),
        hex::encode(&pub_id.x25519.as_bytes()[..8]));
    println!("  ML-DSA-65 ({} B): {}",
        pub_id.mldsa65.as_bytes().len(),
        hex::encode(&pub_id.mldsa65.as_bytes()[..8]));
    println!("  ML-KEM-1024 ({} B): {}",
        pub_id.mlkem1024.as_bytes().len(),
        hex::encode(&pub_id.mlkem1024.as_bytes()[..8]));
    println!();
    println!("Hybride crypto-stack:");
    println!("  signatures:      Ed25519 + ML-DSA-65  (FIPS 204)");
    println!("  key encapsulation: X25519 + ML-KEM-1024 (FIPS 203)");
}
