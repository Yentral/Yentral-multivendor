//! # PHANTOM desktop shell (Tauri 2)
//!
//! Thin GUI wrapper around [`phantom_chat::ChatApp`]. All business logic
//! lives in the workspace crates; the shell here is ≈200 lines of
//! Tauri command handlers that expose the same verbs as the REPL.
//!
//! ## Build requirements
//!
//! Linux:
//! ```text
//!   sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev \
//!                    librsvg2-dev libayatana-appindicator3-dev
//! ```
//!
//! macOS and Windows: see https://tauri.app for the standard prerequisites.
//!
//! Then from this directory:
//! ```text
//!   cargo tauri dev
//! ```

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

use phantom_chat::ChatApp;
use phantom_crypto::Fingerprint;
use serde::Serialize;
use tauri::State;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    chat: Mutex<Option<Arc<ChatApp>>>,
}

// ---------------------------------------------------------------------------
// Commands exposed to the webview
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct IdentityInfo {
    fingerprint: String,
    peer_id: String,
    mnemonic: Option<String>,
}

#[tauri::command]
async fn bootstrap(state: State<'_, AppState>) -> Result<IdentityInfo, String> {
    let (app, mnemonic) = ChatApp::bootstrap_new().await.map_err(|e| e.to_string())?;
    let app = Arc::new(app);
    let fp = app.fingerprint().display();
    let peer_id = app
        .local_peer_id()
        .await
        .map(|p| p.to_string())
        .map_err(|e| e.to_string())?;
    *state.chat.lock().await = Some(app);
    Ok(IdentityInfo {
        fingerprint: fp,
        peer_id,
        mnemonic: Some(mnemonic),
    })
}

#[tauri::command]
async fn recover(
    state: State<'_, AppState>,
    phrase: String,
    passphrase: String,
) -> Result<IdentityInfo, String> {
    let app = ChatApp::bootstrap_recover(&phrase, &passphrase)
        .await
        .map_err(|e| e.to_string())?;
    let app = Arc::new(app);
    let fp = app.fingerprint().display();
    let peer_id = app
        .local_peer_id()
        .await
        .map(|p| p.to_string())
        .map_err(|e| e.to_string())?;
    *state.chat.lock().await = Some(app);
    Ok(IdentityInfo {
        fingerprint: fp,
        peer_id,
        mnemonic: None,
    })
}

#[tauri::command]
async fn listen_on(state: State<'_, AppState>, addr: String) -> Result<String, String> {
    let app = state.chat.lock().await.clone().ok_or("not bootstrapped")?;
    let parsed = addr.parse().map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
    let bound = app.listen_on(parsed).await.map_err(|e| e.to_string())?;
    Ok(bound.to_string())
}

#[tauri::command]
async fn dial(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    let app = state.chat.lock().await.clone().ok_or("not bootstrapped")?;
    let parsed = addr.parse().map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
    app.dial(parsed).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_chat(
    state: State<'_, AppState>,
    fingerprint: String,
    body: String,
) -> Result<(), String> {
    let app = state.chat.lock().await.clone().ok_or("not bootstrapped")?;
    let fp = Fingerprint::parse(&fingerprint).map_err(|e| e.to_string())?;
    app.send_chat(fp, &body).await.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            chat: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap, recover, listen_on, dial, send_chat,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PHANTOM desktop");
}
