use jacquard::CowStr;
use jacquard::client::FileAuthStore;
use jacquard::oauth::atproto::AtprotoClientMetadata;
use jacquard::oauth::client::{OAuthClient, OAuthSession};
use jacquard::oauth::loopback::LoopbackConfig;
use jacquard::oauth::session::ClientData;
use jacquard::oauth::types::CallbackParams;
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
    let redirect = match Url::parse(&format!("http://127.0.0.1:{LOOPBACK_PORT}/oauth/callback")) {
        Ok(url) => url,
        Err(_) => unreachable!("the fixed loopback callback URL is valid"),
    };
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

/// Login via OAuth loopback flow — opens browser for authorization.
pub async fn login(handle: &str) -> Result<SessionInfo> {
    let session = oauth_client()
        .login_with_local_server(handle, Default::default(), LoopbackConfig::default())
        .await
        .map_err(|e| miette!("OAuth login failed: {e}"))?;
    save_session_info(&session, handle).await
}

/// Login without a browser on this machine.
pub async fn login_headless(handle: &str) -> Result<SessionInfo> {
    let oauth = oauth_client();
    let authorization_url = oauth
        .start_auth(handle, Default::default())
        .await
        .map_err(|e| miette!("OAuth login failed: {e}"))?;

    println!("\nVisit this URL in a browser on any machine:\n\n{authorization_url}\n");
    println!(
        "After approving access, the browser will fail to reach 127.0.0.1:4000. \
         Copy that complete URL from its address bar and paste it at the hidden prompt."
    );
    let callback_url = rpassword::prompt_password("Callback URL: ").into_diagnostic()?;

    let session = oauth
        .callback(parse_callback_url(callback_url.trim())?)
        .await
        .map_err(|e| miette!("OAuth login failed: {e}"))?;
    save_session_info(&session, handle).await
}

fn parse_callback_url(callback_url: &str) -> Result<CallbackParams<'static>> {
    let url = Url::parse(callback_url)
        .map_err(|_| miette!("Paste the complete callback URL from your browser's address bar."))?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port_or_known_default() != Some(LOOPBACK_PORT)
        || url.path() != "/oauth/callback"
    {
        return Err(miette!(
            "The callback URL must be http://127.0.0.1:4000/oauth/callback?..."
        ));
    }

    let mut code = None;
    let mut state = None;
    let mut iss = None;
    for (key, value) in url.query_pairs() {
        let target = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "iss" => &mut iss,
            _ => continue,
        };
        if target.replace(value.into_owned()).is_some() {
            return Err(miette!(
                "The callback URL contains duplicate {} parameters.",
                key
            ));
        }
    }

    let code = code
        .filter(|value| !value.is_empty())
        .ok_or_else(|| miette!("The callback URL is missing its code parameter."))?;
    let state = state
        .filter(|value| !value.is_empty())
        .ok_or_else(|| miette!("The callback URL is missing its state parameter."))?;
    Ok(CallbackParams {
        code: CowStr::from(code),
        state: Some(CowStr::from(state)),
        iss: iss.map(CowStr::from),
    })
}

async fn save_session_info(session: &Session, handle: &str) -> Result<SessionInfo> {
    let (did, session_id) = session.session_info().await;
    let info = SessionInfo {
        did: did.to_string(),
        handle: handle.to_string(),
        session_id: session_id.to_string(),
    };

    // Persist session info with restrictive permissions (0600 atomically on Unix)
    let json = serde_json::to_string_pretty(&info).into_diagnostic()?;
    config::write_private_file(&config::session_info_path(), json.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_callback_url() {
        let params = match parse_callback_url(
            "http://127.0.0.1:4000/oauth/callback?code=code-123&state=state-123&iss=https%3A%2F%2Fentryway.example",
        ) {
            Ok(params) => params,
            Err(error) => panic!("valid callback URL rejected: {error}"),
        };

        assert_eq!(params.code.as_ref(), "code-123");
        assert_eq!(params.state.as_deref(), Some("state-123"));
        assert_eq!(params.iss.as_deref(), Some("https://entryway.example"));
    }

    #[test]
    fn rejects_invalid_callback_urls() {
        assert!(parse_callback_url("https://example.com/oauth/callback?code=x&state=y").is_err());
        assert!(parse_callback_url("http://127.0.0.1:4000/oauth/callback?code=x").is_err());
        assert!(parse_callback_url("http://127.0.0.1:4000/oauth/callback?code=&state=y").is_err());
        assert!(parse_callback_url("http://127.0.0.1:4000/oauth/callback?code=x&state=").is_err());
    }
}
