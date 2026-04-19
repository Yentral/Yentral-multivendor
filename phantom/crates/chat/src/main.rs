//! `phantom-chat` — interactive REPL desktop client.
//!
//! Commands (prefix with `/`):
//!
//! ```text
//!   /id                  show your fingerprint + peer id + listen addr
//!   /listen <multiaddr>  start listening (default /ip4/0.0.0.0/tcp/0)
//!   /dial <multiaddr>    connect to a peer (must contain /p2p/<peer>)
//!   /contact <fp> <name> register a contact (peer id optional)
//!   /open <fp>           open session with a contact
//!   /send <fp> <text>    send a chat message
//!   /inbox               flush pending received messages
//!   /audit               decrypt and dump the local audit log
//!   /quit                exit
//! ```
//!
//! For Sprint 6 this is a demo client — single-binary, single-device,
//! no persistence. Future sprints add on-disk identity storage, TUI mode,
//! and the Tauri GUI shell in `/desktop`.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use phantom_chat::{ChatApp, ChatError};
use phantom_crypto::Fingerprint;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                PHANTOM chat — REPL client                 ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("Bootstrap nieuwe identiteit...");
    let (app, mnemonic) = ChatApp::bootstrap_new().await?;
    let app = Arc::new(app);
    println!("Adres:    {}", app.fingerprint());
    println!("Peer-id:  {}", app.local_peer_id().await?);
    println!();
    println!("Zaadwoorden (SCHRIJF OP):");
    for (i, w) in mnemonic.split_whitespace().enumerate() {
        print!("{:>2}. {:<10}  ", i + 1, w);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();
    println!("Typ /help voor commando's.");

    // Spawn inbound-print loop.
    {
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            loop {
                match app.next_inbound().await {
                    Ok(Some((fp, payload))) => print_inbound(&fp, &payload),
                    Ok(None) => {}
                    Err(e) => eprintln!("[inbound] error: {e}"),
                }
            }
        });
    }

    // REPL.
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    print!("> ");
    stdout.flush()?;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            print!("> ");
            stdout.flush()?;
            continue;
        }
        if let Err(e) = dispatch(&app, &line).await {
            eprintln!("error: {e}");
        }
        if line.trim() == "/quit" {
            break;
        }
        print!("> ");
        stdout.flush()?;
    }
    Ok(())
}

fn print_inbound(fp: &Fingerprint, payload: &phantom_protocol::SealedPayload) {
    use phantom_protocol::SealedPayload::*;
    match payload {
        Chat { body, .. } => println!("\n[{fp}] {body}\n> "),
        Mail { subject, body, .. } => println!("\n[{fp}] ✉️ {subject}\n  {body}\n> "),
        File { name, data, .. } => println!("\n[{fp}] 📎 {name} ({} KiB)\n> ", data.len() / 1024),
        Receipt { .. } => println!("\n[{fp}] ✔ receipt\n> "),
        Presence { kind, .. } => println!("\n[{fp}] presence: {kind:?}\n> "),
    }
    let _ = io::stdout().flush();
}

async fn dispatch(app: &ChatApp, line: &str) -> Result<(), ChatError> {
    let mut parts = line.splitn(3, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "/help" => {
            println!(
                "  /id\n  /listen <multiaddr>\n  /dial <multiaddr>\n  \
                 /contact <fp> <name>\n  /open <fp>\n  /send <fp> <text>\n  \
                 /inbox\n  /audit\n  /quit"
            );
            Ok(())
        }
        "/id" => {
            println!("  fp:       {}", app.fingerprint());
            println!("  peer-id:  {}", app.local_peer_id().await?);
            Ok(())
        }
        "/listen" => {
            let addr = parts
                .next()
                .unwrap_or("/ip4/0.0.0.0/tcp/0")
                .parse()
                .map_err(|e: libp2p::multiaddr::Error| ChatError::Message(e.to_string()))?;
            let bound = app.listen_on(addr).await?;
            println!("  listening on {bound}");
            Ok(())
        }
        "/dial" => {
            let addr: libp2p::Multiaddr = parts
                .next()
                .ok_or_else(|| ChatError::Message("usage: /dial <multiaddr>".into()))?
                .parse()
                .map_err(|e: libp2p::multiaddr::Error| ChatError::Message(e.to_string()))?;
            app.dial(addr).await?;
            println!("  dialed");
            Ok(())
        }
        "/contact" => {
            let fp_str = parts
                .next()
                .ok_or_else(|| ChatError::Message("usage: /contact <fp> <name>".into()))?;
            let name = parts
                .next()
                .ok_or_else(|| ChatError::Message("usage: /contact <fp> <name>".into()))?
                .to_string();
            let fp = Fingerprint::parse(fp_str)
                .map_err(|e| ChatError::Message(format!("bad fingerprint: {e}")))?;
            app.add_contact(fp, name, None).await;
            println!("  added");
            Ok(())
        }
        "/send" => {
            let fp_str = parts
                .next()
                .ok_or_else(|| ChatError::Message("usage: /send <fp> <text>".into()))?;
            let body = parts
                .next()
                .ok_or_else(|| ChatError::Message("usage: /send <fp> <text>".into()))?;
            let fp = Fingerprint::parse(fp_str)
                .map_err(|e| ChatError::Message(format!("bad fingerprint: {e}")))?;
            app.send_chat(fp, body).await?;
            println!("  sent");
            Ok(())
        }
        "/audit" => {
            let audit = app.audit.lock().await;
            let events = audit
                .read_all(&app.identity.storage_key.0)
                .map_err(ChatError::Audit)?;
            println!("  {} events", events.len());
            for (i, e) in events.iter().enumerate() {
                println!("  {i:>3}: @min={:<8}  {:?}", e.timestamp_minute, e.kind);
            }
            Ok(())
        }
        "/inbox" => {
            println!("  (messages print automatically as they arrive)");
            Ok(())
        }
        "/quit" => {
            println!("bye");
            Ok(())
        }
        other => Err(ChatError::Message(format!("unknown command: {other}"))),
    }
}
