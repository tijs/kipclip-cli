//! Explicit app-password login. Passwords are read only here, from this process's
//! environment. There is no vault command, subprocess, fallback login, or password
//! persistence. Jacquard's credential login/refresh helpers persist before caller
//! identity validation. Reuse its typed XRPC/session/store APIs, not those helpers.

use std::env::VarError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jacquard::api::com_atproto::server::create_session::CreateSession;
use jacquard::api::com_atproto::server::refresh_session::RefreshSession;
use jacquard::client::credential_session::SessionKey;
use jacquard::client::{AtpSession, SessionStore, SessionStoreError};

use jacquard::http_client::HttpClient;
use jacquard::types::string::Handle;
use jacquard::xrpc::{CallOptions, XrpcRequest, XrpcResponse};
use jacquard::{AuthorizationToken, CowStr, IntoStatic};

use jacquard_identity::resolver::IdentityResolver;
use miette::{Result, miette};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use url::Url;
use zeroize::Zeroizing;

use super::auth::{AuthMethod, RequestFailure, SessionInfo};
use super::config;

mod discovery;
mod transport;
pub use transport::SessionHttp;
use transport::{MAX_AUTH_BODY, expired_token, send_xrpc};

const SESSION_ID: &str = "app-password";

pub struct AppSession<T = SessionHttp> {
    store: PrivateSessionStore,
    key: SessionKey,
    http: Arc<T>,
    pds: Url,
}

impl<T: HttpClient + Send + Sync + 'static> AppSession<T> {
    pub async fn send<R>(&self, request: R) -> std::result::Result<XrpcResponse<R>, RequestFailure>
    where
        R: XrpcRequest + Send + Sync,
        R::Response: Send + Sync,
    {
        let session = self.store.get(&self.key).await.ok_or(RequestFailure)?;
        let mut options = CallOptions {
            auth: Some(AuthorizationToken::Bearer(session.access_jwt)),
            ..Default::default()
        };
        let response = send_xrpc(&*self.http, &self.pds, &request, &options, true).await?;
        // Jacquard 0.9's credential send only recognizes Auth(TokenExpired).
        // Its open-union endpoint errors can parse a 400 ExpiredToken as Xrpc
        // instead. Inspect the protocol's exact error code on BOTH 400 and 401,
        // never arbitrary message text; refresh and retry at most once.
        if !expired_token(response.status(), response.buffer()) {
            return Ok(response);
        }
        options.auth = Some(self.refresh().await?);
        send_xrpc(&*self.http, &self.pds, &request, &options, false).await
    }

    async fn refresh(&self) -> std::result::Result<AuthorizationToken<'static>, RequestFailure> {
        let session = self.store.get(&self.key).await.ok_or(RequestFailure)?;
        let options = CallOptions {
            auth: Some(AuthorizationToken::Bearer(session.refresh_jwt.clone())),
            ..Default::default()
        };
        let response = send_xrpc(&*self.http, &self.pds, &RefreshSession, &options, false).await?;
        let output = response.parse().map_err(|_| RequestFailure)?;
        if !matches_account(
            response.buffer(),
            session.did.as_str(),
            session.handle.as_str(),
        ) {
            return Err(RequestFailure);
        }
        let refreshed = AtpSession::from(output);
        let token = AuthorizationToken::Bearer(refreshed.access_jwt.clone());
        // The validated store checks identity again and writes atomically before
        // any retry can use the rotated token. Never re-read an app password.
        self.store
            .compare_and_swap(&self.key, &session, refreshed)
            .await
            .map_err(|_| RequestFailure)?;
        Ok(token)
    }
}

fn matches_account(bytes: &[u8], did: &str, handle: &str) -> bool {
    #[derive(Deserialize)]
    struct Account<'a> {
        did: &'a str,
        handle: &'a str,
        active: Option<bool>,
    }
    // Compare original JSON strings as well as typed output: Handle's parser
    // would otherwise strip an unexpected @ or at:// prefix from a response.
    serde_json::from_slice::<Account<'_>>(bytes).is_ok_and(|account| {
        account.did == did && account.handle == handle && account.active != Some(false)
    })
}

// No Debug/Display/Serialize implementation: a password must never be printable.
struct AppPassword(Zeroizing<String>);

fn input_error(reason: &'static str) -> miette::Report {
    miette!(
        "KIP_APP_PASSWORD_ENV: {reason} Supply only the environment-variable name in arguments, never its value or a password file."
    )
}

fn requested_handle(raw: &str) -> Result<Handle<'_>> {
    let handle = Handle::new(raw)
        .map_err(|_| miette!("KIP_LOGIN_INPUT: Supply a valid bare AT Protocol handle."))?;
    // Jacquard accepts/strips @ and at:// prefixes; do not silently change the
    // explicitly requested identity, and do not accept handle.invalid.
    if handle.as_str() != raw || !handle.is_valid() {
        return Err(miette!(
            "KIP_LOGIN_INPUT: Supply a valid bare AT Protocol handle."
        ));
    }
    Ok(handle)
}

fn password_from_env_with(
    name: &str,
    read: impl FnOnce(&str) -> std::result::Result<String, VarError>,
) -> Result<AppPassword> {
    // Never interpolate even the supplied name in errors; someone may have
    // mistakenly supplied a secret instead of a variable name.
    let mut bytes = name.bytes();
    if name.len() > 128
        || !bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(input_error(
            "Invalid environment-variable name; use ASCII letters, digits and underscores, starting with a letter or underscore (up to 128 characters).",
        ));
    }
    let value = Zeroizing::new(read(name).map_err(|error| match error {
        VarError::NotPresent => input_error("The selected environment variable is not set in this login process. Inject it into the same kip invocation."),
        VarError::NotUnicode(_) => input_error("The selected environment variable is not valid UTF-8."),
    })?);
    if value.is_empty() {
        return Err(input_error("The selected environment variable is empty."));
    }
    // The createSession lexicon treats passwords as opaque strings. Do not
    // invent a provider-specific password grammar or trim/normalize the value.
    if value.len() > 1024
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(input_error(
            "The selected environment variable has an invalid app-password value (maximum 1024 bytes; no whitespace or control characters).",
        ));
    }
    Ok(AppPassword(value))
}

/// No user-supplied PDS override: discover the requested handle's DID document.
/// This function is called only by the explicit `login --app-password-env` arm.
pub async fn login_env(handle: &str, env_name: &str) -> Result<SessionInfo> {
    let handle = requested_handle(handle)?;
    let password = password_from_env_with(env_name, |name| std::env::var(name))?;
    let http = SessionHttp;
    let resolver = discovery::DiscoveryResolver::new()?;
    login_with(
        &resolver,
        &http,
        &handle,
        password,
        &config::session_info_path(),
    )
    .await
}

async fn login_with(
    resolver: &(impl IdentityResolver + Sync),
    http: &(impl HttpClient + Sync),
    handle: &Handle<'_>,
    password: AppPassword,
    path: &Path,
) -> Result<SessionInfo> {
    let (did, pds) = resolve_account(resolver, handle).await?;
    let request = CreateSession {
        identifier: CowStr::Borrowed(handle.as_str()),
        password: CowStr::Borrowed(password.0.as_str()),
        allow_takendown: Some(false),
        auth_factor_token: None,
        extra_data: None,
    };
    let response = send_xrpc(http, &pds, &request, &CallOptions::default(), false).await
        .map_err(|_| miette!("KIP_APP_LOGIN_FAILED: PDS session creation failed. Check the connection and app-password authorization."))?;
    // The request only borrowed the password. No helper spawns a child process.
    drop(request);
    let output = response.parse().map_err(|_| {
        miette!(
            "KIP_APP_LOGIN_FAILED: PDS rejected session creation or returned an invalid response."
        )
    })?;
    if !matches_account(response.buffer(), did.as_str(), handle.as_str()) {
        return Err(miette!(
            "KIP_ACCOUNT_MISMATCH: The PDS session did not match the requested active account. No session was saved."
        ));
    }
    let session = AtpSession::from(output);
    if session.access_jwt.contains(password.0.as_str())
        || session.refresh_jwt.contains(password.0.as_str())
    {
        return Err(miette!(
            "KIP_APP_LOGIN_FAILED: PDS returned invalid session material. No session was saved."
        ));
    }
    // No password (including an accidental echo in a token field) can reach the
    // persistence layer. Zeroize our owned copy before encoding any session.
    drop(password);
    validate_tokens(&session).map_err(|_| {
        miette!(
            "KIP_APP_LOGIN_FAILED: PDS returned invalid session material. No session was saved."
        )
    })?;
    let info = SessionInfo {
        did: did.to_string(),
        handle: handle.to_string(),
        session_id: SESSION_ID.into(),
        auth_method: AuthMethod::AppPassword,
    };
    // One atomic active-session file avoids a token/identity two-file commit.
    // We save only tokens, verified identity and routing, not the raw response,
    // email, DID document, environment-variable name, or app password.
    let mut generation = [0_u8; 32];
    getrandom::fill(&mut generation)
        .map_err(|_| miette!("KIP_STORE_FAILED: Could not initialize session identity."))?;
    let generation = generation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let saved = SavedAppSession::from_session(info.clone(), pds, session, generation);
    saved.persist(path)?;
    Ok(info)
}

async fn resolve_account(
    resolver: &(impl IdentityResolver + Sync),
    handle: &Handle<'_>,
) -> Result<(jacquard::types::string::Did<'static>, Url)> {
    let did = resolver
        .resolve_handle(handle)
        .await
        .map_err(|_| miette!("KIP_IDENTITY_FAILED: Could not resolve the requested account."))?;
    let response = resolver.resolve_did_doc(&did).await.map_err(|_| {
        miette!("KIP_IDENTITY_FAILED: Could not resolve the account's DID document.")
    })?;
    // Parse original strings, never Jacquard's normalizing Did/Handle types.
    // A duplicate JSON id/service field is rejected by serde's struct decoder.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Document {
        id: String,
        also_known_as: Vec<String>,
        #[serde(default)]
        service: Vec<Service>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Service {
        id: String,
        #[serde(rename = "type")]
        kind: String,
        service_endpoint: Option<serde_json::Value>,
    }
    if response.status != http::StatusCode::OK || response.buffer.len() > MAX_AUTH_BODY {
        return Err(miette!(
            "KIP_IDENTITY_FAILED: Invalid account DID document."
        ));
    }
    let doc: Document = serde_json::from_slice(&response.buffer)
        .map_err(|_| miette!("KIP_IDENTITY_FAILED: Invalid account DID document."))?;
    // Require bidirectional handle binding, not just a DNS assertion, and an
    // exact DID document id before sending a password to the advertised PDS.
    let alias = format!("at://{}", handle.as_str());
    if doc.id != did.as_str() || !doc.also_known_as.contains(&alias) {
        return Err(miette!(
            "KIP_IDENTITY_FAILED: The account's handle and DID document do not match."
        ));
    }
    // Service type alone is not an authority. Refuse ANY duplicate canonical
    // identifier, including duplicates with a different type or endpoint.
    let mut services = doc
        .service
        .iter()
        .filter(|service| service.id == "#atproto_pds");
    let canonical = services
        .next()
        .filter(|service| service.kind == "AtprotoPersonalDataServer" && services.next().is_none())
        .ok_or_else(|| {
            miette!("KIP_IDENTITY_FAILED: Missing or ambiguous canonical PDS service.")
        })?;
    let pds = canonical
        .service_endpoint
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Url::parse(value).ok())
        .ok_or_else(|| miette!("KIP_IDENTITY_FAILED: Invalid canonical PDS endpoint."))?;
    validate_pds(&pds)?;
    Ok((did.into_static(), pds))
}

fn validate_pds(pds: &Url) -> Result<()> {
    if pds.scheme() != "https"
        || pds.host_str().is_none()
        || !pds.username().is_empty()
        || pds.password().is_some()
        || pds.query().is_some()
        || pds.fragment().is_some()
    {
        return Err(miette!(
            "KIP_PDS_INVALID: The account requires a credential-free HTTPS PDS endpoint without a query or fragment."
        ));
    }
    // Literals cannot be protected with reqwest DNS overrides. Domains are
    // resolved, checked in full and pinned by SessionHttp on EVERY request.
    let literal = match pds.host() {
        Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    };
    if literal.is_some_and(super::fetch::is_forbidden_ip) {
        return Err(miette!(
            "KIP_PDS_INVALID: Local, private and reserved PDS addresses are unsupported."
        ));
    }
    Ok(())
}

fn validate_tokens(session: &AtpSession) -> std::result::Result<(), SessionStoreError> {
    // JWT syntax only, not a claim/signature trust decision: the issuer is the
    // identity-discovered PDS over TLS. This also rejects accidental password or
    // raw error-body echoes in token fields before anything is persisted.
    for token in [&session.access_jwt, &session.refresh_jwt] {
        let mut parts = token.split('.');
        let valid = (0..3).all(|_| {
            parts.next().is_some_and(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
        });
        if token.len() > 16 * 1024 || !valid || parts.next().is_some() {
            return Err(rejected_session());
        }
    }
    Ok(())
}

fn rejected_session() -> SessionStoreError {
    SessionStoreError::Other(
        "KIP_SESSION_REJECTED: Invalid, mismatched or superseded session material.".into(),
    )
}

// Intentionally no Debug; never expose this through whoami or error sources.
#[derive(Serialize, Deserialize)]
struct SavedAppSession {
    #[serde(flatten)]
    info: SessionInfo,
    pds: Url,
    access_jwt: String,
    refresh_jwt: String,
    // Legacy app sessions have no generation. Fresh logins always get a new
    // random generation, even if a PDS happens to return identical JWTs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    generation: String,
}

impl SavedAppSession {
    fn from_session(info: SessionInfo, pds: Url, session: AtpSession, generation: String) -> Self {
        Self {
            info,
            pds,
            access_jwt: session.access_jwt.to_string(),
            refresh_jwt: session.refresh_jwt.to_string(),
            generation,
        }
    }

    fn session(&self) -> Result<AtpSession> {
        if self.info.auth_method != AuthMethod::AppPassword || self.info.session_id != SESSION_ID {
            return Err(miette!(
                "KIP_RESTORE_FAILED: Invalid app-password session metadata."
            ));
        }
        let session = AtpSession {
            access_jwt: CowStr::from(self.access_jwt.clone()),
            refresh_jwt: CowStr::from(self.refresh_jwt.clone()),
            did: jacquard::types::string::Did::new_owned(&self.info.did)
                .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached account identity."))?,
            handle: requested_handle(&self.info.handle)
                .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached account identity."))?
                .into_static(),
        };
        validate_pds(&self.pds)
            .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached PDS endpoint."))?;
        validate_tokens(&session)
            .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid cached session material."))?;
        Ok(session)
    }

    fn encoded(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(serde_json::to_vec(self).map_err(|_| {
            miette!("KIP_STORE_FAILED: Could not encode the local session.")
        })?))
    }

    fn persist(&self, path: &Path) -> Result<()> {
        config::write_private_file(path, &self.encoded()?)
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(config::read_private_file(path).map_err(|_| {
            miette!("KIP_RESTORE_FAILED: Could not read the app-password session store.")
        })?);
        serde_json::from_slice(&bytes)
            .map_err(|_| miette!("KIP_RESTORE_FAILED: Invalid app-password session store."))
    }
}

/// The validated store is the final enforcement point for refresh:
/// refuse a different DID/handle before saving or activating replacement tokens.
/// Unlike FileAuthStore, this has atomic 0600 writes and does not swallow reads.
pub struct PrivateSessionStore {
    path: PathBuf,
    current: RwLock<SavedAppSession>,
    #[cfg(test)]
    before_replace: Option<Box<dyn Fn() + Send + Sync>>,
}

impl PrivateSessionStore {
    async fn compare_and_swap(
        &self,
        key: &SessionKey,
        expected: &AtpSession,
        session: AtpSession,
    ) -> std::result::Result<(), SessionStoreError> {
        let mut saved = self.current.write().await;
        if key.0.as_str() != saved.info.did
            || key.1.as_str() != saved.info.session_id
            || session.did.as_str() != saved.info.did
            || session.handle.as_str() != saved.info.handle
            || expected.access_jwt.as_str() != saved.access_jwt
            || expected.refresh_jwt.as_str() != saved.refresh_jwt
        {
            return Err(rejected_session());
        }
        validate_tokens(&session)?;
        // The RwLock is only in-process. This OS lock is shared by all active
        // session writers, OAuth activation and logout. Hold it across the
        // disk re-check AND atomic replacement, not across network requests.
        let transaction =
            config::SessionTransaction::acquire(&self.path).map_err(|_| rejected_session())?;
        let disk = SavedAppSession::read(&self.path).map_err(|_| rejected_session())?;
        if disk.info != saved.info
            || disk.pds != saved.pds
            || disk.access_jwt != saved.access_jwt
            || disk.refresh_jwt != saved.refresh_jwt
            || disk.generation != saved.generation
        {
            return Err(rejected_session());
        }
        #[cfg(test)]
        if let Some(hook) = &self.before_replace {
            hook();
        }
        let replacement = SavedAppSession::from_session(
            saved.info.clone(),
            saved.pds.clone(),
            session,
            saved.generation.clone(),
        );
        transaction
            .write(
                &self.path,
                &replacement.encoded().map_err(|_| rejected_session())?,
            )
            .map_err(|_| rejected_session())?;
        *saved = replacement;
        Ok(())
    }
}

impl SessionStore<SessionKey, AtpSession> for PrivateSessionStore {
    async fn get(&self, key: &SessionKey) -> Option<AtpSession> {
        let saved = self.current.read().await;
        if key.0.as_str() != saved.info.did || key.1.as_str() != saved.info.session_id {
            return None;
        }
        saved.session().ok()
    }

    async fn set(
        &self,
        key: SessionKey,
        session: AtpSession,
    ) -> std::result::Result<(), SessionStoreError> {
        let expected = self.get(&key).await.ok_or_else(rejected_session)?;
        self.compare_and_swap(&key, &expected, session).await
    }

    async fn del(&self, _key: &SessionKey) -> std::result::Result<(), SessionStoreError> {
        // CLI logout clears the active file explicitly, never as an automatic
        // error-recovery side effect of a read or a failed refresh.
        Err(rejected_session())
    }
}

pub fn restore(info: &SessionInfo) -> Result<AppSession> {
    restore_with(info, &config::session_info_path(), SessionHttp)
}

fn restore_with<T: HttpClient + Send + Sync + 'static>(
    info: &SessionInfo,
    path: &Path,
    http: T,
) -> Result<AppSession<T>> {
    let saved = SavedAppSession::read(path)?;
    let material = saved.session()?;
    if saved.info != *info {
        return Err(miette!(
            "KIP_RESTORE_FAILED: Cached session identity does not match the active session."
        ));
    }
    let key = SessionKey(material.did, CowStr::new_static(SESSION_ID));
    let pds = saved.pds.clone();
    let store = PrivateSessionStore {
        path: path.into(),
        current: RwLock::new(saved),
        #[cfg(test)]
        before_replace: None,
    };
    Ok(AppSession {
        store,
        key,
        http: Arc::new(http),
        pds,
    })
}

#[cfg(test)]
mod tests;
