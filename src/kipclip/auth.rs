use std::io::{self, Write};

use jacquard::CowStr;

use jacquard::oauth::atproto::AtprotoClientMetadata;
use jacquard::oauth::client::{OAuthClient, OAuthSession};
use jacquard::oauth::dpop::DpopExt;
use jacquard::oauth::error::OAuthError;
use jacquard::oauth::resolver::OAuthResolver;
use jacquard::oauth::scopes::Scope;
use jacquard::oauth::session::ClientData;
use jacquard::oauth::types::CallbackParams;
use jacquard::xrpc::{XrpcClient, XrpcRequest, XrpcResponse};
use jacquard_identity::JacquardResolver;
use miette::{Result, miette};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::kipclip::{app_session, config};

mod oauth_store;
use oauth_store::OAuthStore;

type OAuth = OAuthSession<JacquardResolver, OAuthStore>;

/// Deliberately holds no upstream error/source, response body, or account data.
#[derive(Debug)]
pub struct RequestFailure;

impl std::fmt::Display for RequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KIP_AUTH_REQUEST_FAILED: Authenticated PDS request failed.")
    }
}

impl std::error::Error for RequestFailure {}

/// Keep Jacquard's OAuth and credential sessions behind the same typed PDS API.
pub enum Session<T = app_session::SessionHttp> {
    OAuth(Box<OAuth>),
    AppPassword(Box<app_session::AppSession<T>>),
}

impl<T: jacquard::http_client::HttpClient + Send + Sync + 'static> Session<T> {
    pub async fn send<R>(&self, request: R) -> std::result::Result<XrpcResponse<R>, RequestFailure>
    where
        R: XrpcRequest + Send + Sync,
        R::Response: Send + Sync,
    {
        match self {
            Self::OAuth(session) => session.send(request).await.map_err(|_| RequestFailure),
            Self::AppPassword(session) => session.send(request).await,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    #[default]
    #[serde(rename = "oauth")]
    OAuth,
    AppPassword,
}

impl AuthMethod {
    fn is_oauth(&self) -> bool {
        *self == Self::OAuth
    }
}

/// Redirect metadata only: neither OAuth login mode starts a callback listener.
const LOOPBACK_PORT: u16 = 4000;
const OAUTH_SCOPE: &str = "atproto transition:generic";

/// Stored session info (persisted separately from OAuth tokens)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub session_id: String,
    // Legacy whoami.json files have no discriminator: they remain OAuth.
    #[serde(default, skip_serializing_if = "AuthMethod::is_oauth")]
    pub auth_method: AuthMethod,
}

/// Keep the existing loopback redirect metadata for pasted-callback login.
/// The client_id URL must include the same redirect_uri and scope params
/// so that token refresh sends the correct client_id to the PDS.
fn loopback_client_metadata() -> AtprotoClientMetadata<'static> {
    let redirect = match Url::parse(&format!("http://127.0.0.1:{LOOPBACK_PORT}/oauth/callback")) {
        Ok(url) => url,
        Err(_) => unreachable!("the fixed loopback callback URL is valid"),
    };
    AtprotoClientMetadata::new_localhost(
        Some(vec![redirect]),
        Some(Scope::parse_multiple(OAUTH_SCOPE).expect("the fixed OAuth scope is valid")),
    )
}

/// Create an OAuth client with file-backed auth store.
/// Uses client metadata that matches the login flow so token refresh works.
async fn oauth_client() -> Result<OAuthClient<JacquardResolver, OAuthStore>> {
    oauth_client_at(&config::auth_store_path()).await
}

async fn oauth_client_at(
    path: &std::path::Path,
) -> Result<OAuthClient<JacquardResolver, OAuthStore>> {
    Ok(oauth_client_from_store(OAuthStore::login_at(path).await?))
}

fn oauth_client_from_store(store: OAuthStore) -> OAuthClient<JacquardResolver, OAuthStore> {
    let client_data = ClientData {
        keyset: None,
        config: loopback_client_metadata(),
    };
    OAuthClient::new(store, client_data)
}

/// Both modes paste a hidden callback; only the default also opens the browser.
pub async fn login(handle: &str, headless: bool) -> Result<SessionInfo> {
    let oauth = oauth_client().await?;
    login_with_oauth(
        &oauth,
        handle,
        headless,
        |url| open::that(url),
        |prompt| rpassword::prompt_password(prompt),
        &mut io::stdout(),
    )
    .await
}

/// Inject only terminal/browser I/O and the resolver for offline flow tests.
/// The same OAuthStore retains its transaction through approval and activation.
async fn login_with_oauth<T: OAuthResolver + DpopExt + Send + Sync + 'static>(
    oauth: &OAuthClient<T, OAuthStore>,
    handle: &str,
    headless: bool,
    open_browser: impl FnOnce(&str) -> io::Result<()>,
    read_callback: impl FnOnce(&str) -> io::Result<String>,
    output: &mut impl Write,
) -> Result<SessionInfo> {
    let authorization_url = oauth
        .start_auth(handle, Default::default())
        .await
        .map_err(|_| miette!("KIP_OAUTH_LOGIN_FAILED: OAuth authorization failed. Check the connection and retry the explicit login."))?;

    // Print the URL even when opening succeeds, so a browser-launch failure
    // never prevents the user from completing the same manual callback flow.
    writeln!(
        output,
        "\nVisit this URL in a browser on any machine:\n\n{authorization_url}\n\n\
         After approving access, a connection-refused page at \
         http://127.0.0.1:4000/oauth/callback is expected: kip starts no callback server. \
         Copy the complete URL from the browser's address bar and paste it at the hidden prompt."
    )
    .map_err(|_| miette!("Could not print the OAuth login instructions."))?;
    if !headless && open_browser(&authorization_url).is_err() {
        writeln!(
            output,
            "Could not open a browser. Open the URL above manually, then continue here."
        )
        .map_err(|_| miette!("Could not print the OAuth login instructions."))?;
    }
    output
        .flush()
        .map_err(|_| miette!("Could not print the OAuth login instructions."))?;
    let callback_url = Zeroizing::new(
        read_callback("Callback URL: ")
            .map_err(|_| miette!("Could not read the hidden callback URL."))?,
    );

    let session = oauth
        .callback(parse_callback_url(callback_url.trim())?)
        .await
        .map_err(|_| miette!("KIP_OAUTH_LOGIN_FAILED: OAuth authorization failed. Check the connection and retry the explicit login."))?;
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

async fn save_session_info<T: jacquard::oauth::resolver::OAuthResolver>(
    session: &OAuthSession<T, OAuthStore>,
    handle: &str,
) -> Result<SessionInfo> {
    let (did, session_id) = session.session_info().await;
    let info = SessionInfo {
        did: did.to_string(),
        handle: handle.to_string(),
        session_id: session_id.to_string(),
        auth_method: AuthMethod::OAuth,
    };

    session.registry.store.activate(&info)?;
    Ok(info)
}

/// Test-only independent pointer writer for the app-session CAS regressions.
/// Real OAuth activation MUST use the store's existing lifecycle transaction.
#[cfg(test)]
pub(super) fn activate_session_info_at(info: &SessionInfo, path: &std::path::Path) -> Result<()> {
    let json = serde_json::to_string_pretty(&info)
        .map_err(|_| miette!("KIP_STORE_FAILED: Could not encode the local session identity."))?;
    config::write_private_file(path, json.as_bytes())
}

/// Restore a session without mistaking storage/network failures for expiry.
pub async fn restore_session(info: &SessionInfo) -> Result<Session> {
    let did = jacquard::types::string::Did::new(&info.did)
        .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid DID in cached session info."))?;
    if info.auth_method == AuthMethod::AppPassword {
        return app_session::restore(info).map(|session| Session::AppPassword(Box::new(session)));
    }
    let store = OAuthStore::restore_at(&config::auth_store_path(), info).await?;
    let oauth = oauth_client_from_store(store);

    let session = oauth
        .restore(&did, &info.session_id)
        .await
        .map_err(|e| restore_error(&e, &info.handle))?;

    Ok(Session::OAuth(Box::new(session)))
}

fn login_required(_handle: &str) -> miette::Report {
    // No cached account material (even a syntactically valid handle) or upstream
    // error source is safe to include in an authentication diagnostic.
    miette!(
        "KIP_AUTH_REQUIRED: Not logged in or the saved authorization is no longer usable. \
         Run: kip login <handle>\nComplete the browser approval on this computer, then retry."
    )
}

fn restore_error(error: &OAuthError, handle: &str) -> miette::Report {
    // Use Jacquard's typed permanent-failure predicate, never string matching.
    // In particular, FileAuthStore's `Other("not found")` can mean an I/O,
    // parse, or lookup failure; it is NOT proof that authorization expired.
    let permanent = match error {
        OAuthError::Session(error) => error.is_permanent(),
        OAuthError::Request(error) => error.is_permanent(),
        _ => false,
    };
    if permanent {
        return login_required(handle);
    }
    let reason = match error {
        OAuthError::Storage(_) | OAuthError::Session(jacquard::oauth::session::Error::Store(_)) => {
            "session store read, parse, lookup or write failed"
        }
        OAuthError::Resolver(_)
        | OAuthError::Request(_)
        | OAuthError::Session(jacquard::oauth::session::Error::ServerAgent(_)) => {
            "network, server or OAuth request failed"
        }
        _ => "invalid local session or OAuth configuration",
    };
    miette!(
        "KIP_RESTORE_FAILED: Could not restore the saved session: {reason}. \
         Expiry was not confirmed. Check the connection or local session store before retrying; \
         do not reset credentials for this error."
    )
}

/// Get stored session info (DID + handle)
pub fn get_session_info() -> Result<SessionInfo> {
    let path = config::session_info_path();
    let bytes = Zeroizing::new(config::read_private_file(&path).map_err(session_info_read_error)?);
    let data = std::str::from_utf8(&bytes)
        .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached session info encoding."))?;
    parse_session_info(data)
}

fn session_info_read_error(error: std::io::Error) -> miette::Report {
    if error.kind() == std::io::ErrorKind::NotFound {
        login_required("<handle>")
    } else {
        miette!("KIP_RESTORE_FAILED: Could not read cached session info. Check local file access.")
    }
}

fn parse_session_info(data: &str) -> Result<SessionInfo> {
    serde_json::from_str(data)
        .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached session info JSON."))
}

/// Clear all stored auth data
pub fn logout() -> Result<()> {
    config::clear_sessions(&config::config_dir())
}

#[cfg(all(test, unix))]
#[path = "auth/lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "auth/manual_login_tests.rs"]
mod manual_login_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use jacquard::oauth::request::RequestError;
    use jacquard::oauth::session::Error as SessionError;
    use jacquard::session::SessionStoreError;

    fn assert_restore_failure(error: OAuthError) {
        let report = restore_error(&error, "fixture.test");
        for message in [report.to_string(), format!("{report:?}")] {
            assert!(message.contains("KIP_RESTORE_FAILED"), "{message}");
            assert!(!message.contains("kip login"), "{message}");
            assert!(!message.contains("fixture-private-detail"), "{message}");
        }
    }

    #[test]
    fn permanent_session_failures_require_manual_browser_approval() {
        for error in [
            SessionError::SessionNotFound,
            SessionError::RefreshFailed(RequestError::no_refresh_token()),
        ] {
            let report = restore_error(&error.into(), "fixture.test");
            let message = report.to_string();
            assert!(message.contains("KIP_AUTH_REQUIRED"));
            assert!(message.contains("kip login <handle>"));
            assert!(!message.contains("fixture.test"));
            assert!(message.contains("browser approval on this computer"));
        }
    }

    #[test]
    fn revoked_refresh_is_distinct_from_server_or_network_failure() {
        for code in ["invalid_grant", "access_denied"] {
            let request = RequestError::http_status_with_body(
                400.try_into().unwrap(),
                serde_json::json!({"error": code, "error_description": "fixture-private-detail"}),
            );
            let report = restore_error(&SessionError::ServerAgent(request).into(), "fixture.test");
            assert!(report.to_string().contains("KIP_AUTH_REQUIRED"));
            assert!(!format!("{report:?}").contains("fixture-private-detail"));
        }
        for status in [401, 429, 500, 503] {
            let request = RequestError::http_status_with_body(
                status.try_into().unwrap(),
                serde_json::json!({"error": "server_error", "detail": "fixture-private-detail"}),
            );
            assert_restore_failure(SessionError::ServerAgent(request).into());
        }
        let request = RequestError::resolver(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "fixture-private-detail",
        ));
        assert_restore_failure(SessionError::ServerAgent(request).into());
    }

    #[test]
    fn ambiguous_store_lookup_is_not_proof_of_expiry() {
        for detail in ["not found", "fixture-private-detail"] {
            assert_restore_failure(
                SessionError::Store(SessionStoreError::Other(detail.into())).into(),
            );
        }
        assert_restore_failure(OAuthError::Storage(SessionStoreError::Io(
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixture-private-detail",
            ),
        )));
    }

    #[test]
    fn cached_info_missing_is_distinct_from_unreadable_or_malformed() {
        let missing = session_info_read_error(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(missing.to_string().contains("KIP_AUTH_REQUIRED"));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
        ] {
            let report =
                session_info_read_error(std::io::Error::new(kind, "fixture-private-detail"));
            assert!(report.to_string().contains("KIP_RESTORE_FAILED"));
            assert!(!format!("{report:?}").contains("fixture-private-detail"));
            assert!(!report.to_string().contains("kip login"));
        }
        let report = parse_session_info(r#"{"did": "fixture-private-detail"}"#).unwrap_err();
        assert!(report.to_string().contains("KIP_RESTORE_FAILED"));
        assert!(!format!("{report:?}").contains("fixture-private-detail"));
    }

    #[tokio::test]
    async fn invalid_cached_did_fails_before_store_or_network_access() {
        let info = SessionInfo {
            did: "fixture-private-detail".into(),
            handle: "fixture.test".into(),
            session_id: "fixture-only".into(),
            auth_method: AuthMethod::OAuth,
        };
        let report = restore_session(&info).await.err().expect("invalid DID");
        assert!(report.to_string().contains("KIP_RESTORE_FAILED"));
        assert!(!format!("{report:?}").contains("fixture-private-detail"));
    }

    #[test]
    fn recovery_command_does_not_echo_untrusted_cached_text() {
        for handle in [
            "bad\nfixture-private-detail",
            "fixture.test;fixture-private-detail",
        ] {
            let message = login_required(handle).to_string();
            assert!(message.contains("kip login <handle>"));
            assert!(!message.contains("fixture-private-detail"));
        }
    }

    #[test]
    fn client_metadata_requests_write_scope() {
        let metadata = loopback_client_metadata();
        let scopes: Vec<_> = metadata.scopes.iter().map(ToString::to_string).collect();
        assert_eq!(scopes, ["atproto", "transition:generic"]);
    }

    #[test]
    fn existing_oauth_session_info_round_trips_without_a_new_discriminator() {
        let legacy = serde_json::json!({"did":"did:plc:fixtureaccount", "handle":"fixture.test", "session_id":"oauth-state-fixture"});
        let info = parse_session_info(&legacy.to_string()).unwrap();
        assert_eq!(info.auth_method, AuthMethod::OAuth);
        assert_eq!(serde_json::to_value(info).unwrap(), legacy);
        let error = parse_session_info(r#"{"did":"did:plc:fixtureaccount","handle":"fixture.test","session_id":"fixture","auth_method":"fixture-private-detail"}"#).unwrap_err();
        assert!(!format!("{error:?}").contains("fixture-private-detail"));
    }

    #[tokio::test]
    async fn existing_oauth_store_still_uses_jacquard_and_does_not_fallback_to_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let oauth = oauth_client_at(&path).await.unwrap();
        let did = jacquard::types::string::Did::new("did:plc:fixtureaccount").unwrap();
        // A missing entry fails inside the existing FileAuthStore without any
        // OAuth/PDS request. Its ambiguous error remains a restore failure.
        let error = oauth
            .restore(&did, "fixture-private-detail")
            .await
            .err()
            .unwrap();
        let report = restore_error(&error, "fixture-private-detail.test");
        assert!(report.to_string().contains("KIP_RESTORE_FAILED"));
        assert!(!format!("{report:?}").contains("fixture-private-detail"));
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        assert!(!dir.path().join("whoami.json").exists());
    }

    #[tokio::test]
    async fn valid_legacy_oauth_tokens_and_dpop_material_still_restore_offline() {
        use jacquard::oauth::authstore::ClientAuthStore;
        use jacquard::oauth::session::{ClientSessionData, DpopClientData};
        use jacquard::oauth::types::{OAuthTokenType, TokenSet};
        use jacquard::types::string::{Datetime, Did};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let oauth = oauth_client_at(&path).await.unwrap();
        let did = Did::new_static("did:plc:fixtureaccount").unwrap();
        let data = ClientSessionData {
            account_did: did.clone(),
            session_id: "fixture-oauth-state".into(),
            host_url: "https://pds.test".into(),
            authserver_url: "https://issuer.test".into(),
            authserver_token_endpoint: "https://issuer.test/oauth/token".into(),
            authserver_revocation_endpoint: None,
            scopes: Scope::parse_multiple(OAUTH_SCOPE).unwrap(),
            dpop_data: DpopClientData {
                dpop_key: jacquard::oauth::utils::generate_key(&["ES256".into()]).unwrap(),
                dpop_authserver_nonce: "fixture-auth-nonce".into(),
                dpop_host_nonce: "fixture-host-nonce".into(),
            },
            token_set: TokenSet {
                iss: "https://issuer.test".into(),
                sub: did.clone(),
                aud: "https://pds.test".into(),
                scope: Some(OAUTH_SCOPE.into()),
                refresh_token: Some("fixture-oauth-refresh".into()),
                access_token: "fixture-oauth-access".into(),
                token_type: OAuthTokenType::DPoP,
                // Jacquard returns an unexpired stored session without making
                // any network request; the positive path is offline too.
                expires_at: Some(Datetime::new(
                    (chrono::Utc::now() + chrono::TimeDelta::hours(1)).fixed_offset(),
                )),
            },
        };
        oauth.registry.set(data.clone()).await.unwrap();
        let restored = oauth.restore(&did, "fixture-oauth-state").await.unwrap();
        let (actual_did, actual_id) = restored.session_info().await;
        assert_eq!(actual_did, did);
        assert_eq!(actual_id.as_str(), "fixture-oauth-state");
        assert_eq!(restored.base_uri().await.as_str(), "https://pds.test");
        let saved = oauth
            .registry
            .store
            .get_session(&did, "fixture-oauth-state")
            .await
            .unwrap()
            .unwrap();
        assert!(
            saved == data,
            "OAuth tokens, DPoP material, scopes and endpoints must survive unchanged"
        );
        let serialized: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            serialized["did:plc:fixtureaccount_fixture-oauth-state"]
                .get("OAuth")
                .is_some()
        );
        assert!(!dir.path().join("whoami.json").exists());
    }

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
