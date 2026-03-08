use jacquard::client::FileAuthStore;
use jacquard::oauth::client::{OAuthClient, OAuthSession};
use jacquard::oauth::loopback::LoopbackConfig;
use jacquard_identity::JacquardResolver;
use miette::{IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};

use crate::kipclip::config;

/// Concrete session type used throughout the CLI
pub type Session = OAuthSession<JacquardResolver, FileAuthStore>;

/// Stored session info (persisted separately from OAuth tokens)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub session_id: String,
}

/// Create an OAuth client with file-backed auth store
fn oauth_client() -> OAuthClient<JacquardResolver, FileAuthStore> {
    OAuthClient::with_default_config(FileAuthStore::new(&config::auth_store_path()))
}

/// Login via OAuth loopback flow — opens browser for authorization
pub async fn login(handle: &str) -> Result<SessionInfo> {
    let oauth = oauth_client();
    let session = oauth
        .login_with_local_server(handle, Default::default(), LoopbackConfig::default())
        .await
        .map_err(|e| miette!("OAuth login failed: {e}"))?;

    // Extract session info
    let (did, session_id) = session.session_info().await;
    let did_str = did.to_string();
    let sid_str = session_id.to_string();

    // Resolve handle via identity
    let info = SessionInfo {
        did: did_str,
        handle: handle.to_string(),
        session_id: sid_str,
    };

    // Persist session info
    let path = config::session_info_path();
    let json = serde_json::to_string_pretty(&info).into_diagnostic()?;
    std::fs::write(&path, json).into_diagnostic()?;

    Ok(info)
}

/// Restore a session from the file auth store
pub async fn restore_session() -> Result<Session> {
    let info = get_session_info()?;
    let oauth = oauth_client();

    let did = jacquard::types::string::Did::new(&info.did)
        .map_err(|e| miette!("Invalid DID: {e}"))?;

    let session = oauth
        .restore(&did, &info.session_id)
        .await
        .map_err(|e| miette!("Failed to restore session: {e}"))?;

    Ok(session)
}

/// Get stored session info (DID + handle)
pub fn get_session_info() -> Result<SessionInfo> {
    let path = config::session_info_path();
    let data = std::fs::read_to_string(&path)
        .map_err(|_| miette!("Not logged in. Run: kip login <handle>"))?;
    serde_json::from_str(&data).into_diagnostic()
}

/// Clear all stored auth data
pub fn logout() -> Result<()> {
    let config_dir = config::config_dir();
    for file in ["session.json", "whoami.json"] {
        let path = config_dir.join(file);
        if path.exists() {
            std::fs::remove_file(&path).into_diagnostic()?;
        }
    }
    Ok(())
}
