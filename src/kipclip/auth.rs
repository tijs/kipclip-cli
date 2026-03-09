use jacquard::client::FileAuthStore;
use jacquard::oauth::atproto::AtprotoClientMetadata;
use jacquard::oauth::client::{OAuthClient, OAuthSession};
use jacquard::oauth::loopback::LoopbackConfig;
use jacquard::oauth::session::ClientData;
use jacquard_identity::JacquardResolver;
use miette::{IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::kipclip::config;

/// Concrete session type used throughout the CLI
pub type Session = OAuthSession<JacquardResolver, FileAuthStore>;

/// Default loopback port used by jacquard's LoopbackConfig::default()
const LOOPBACK_PORT: u16 = 4000;

/// Stored session info (persisted separately from OAuth tokens)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub session_id: String,
}

/// Build client metadata matching what login_with_local_server uses.
/// The client_id URL must include the same redirect_uri and scope params
/// so that token refresh sends the correct client_id to the PDS.
fn loopback_client_metadata() -> AtprotoClientMetadata<'static> {
    let redirect = Url::parse(&format!("http://127.0.0.1:{LOOPBACK_PORT}/oauth/callback")).unwrap();
    AtprotoClientMetadata::new_localhost(Some(vec![redirect]), None)
}

/// Create an OAuth client with file-backed auth store.
/// Uses client metadata that matches the login flow so token refresh works.
fn oauth_client() -> OAuthClient<JacquardResolver, FileAuthStore> {
    let store = FileAuthStore::new(config::auth_store_path());
    let client_data = ClientData {
        keyset: None,
        config: loopback_client_metadata(),
    };
    OAuthClient::new(store, client_data)
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

    let info = SessionInfo {
        did: did_str,
        handle: handle.to_string(),
        session_id: sid_str,
    };

    // Persist session info with restrictive permissions (0600 atomically on Unix)
    let path = config::session_info_path();
    let json = serde_json::to_string_pretty(&info).into_diagnostic()?;
    config::write_private_file(&path, json.as_bytes())?;

    Ok(info)
}

/// Restore a session from the file auth store
pub async fn restore_session() -> Result<Session> {
    let info = get_session_info()?;
    let oauth = oauth_client();

    let did =
        jacquard::types::string::Did::new(&info.did).map_err(|e| miette!("Invalid DID: {e}"))?;

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
