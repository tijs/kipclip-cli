//! Real processes, real FileAuthStore mutations, synthetic OAuth HTTP only.
//! Pipe barriers choose each race ordering; deadlines are watchdogs, not sleeps
//! used to guess when another process has entered its transaction.

use super::*;
use jacquard::IntoStatic;
use jacquard::http_client::HttpClient;
use jacquard::oauth::authstore::ClientAuthStore;
use jacquard::oauth::resolver::{OAuthResolver, ResolverError};
use jacquard::oauth::session::{AuthRequestData, ClientSessionData, DpopClientData, DpopReqData};
use jacquard::oauth::types::{OAuthAuthorizationServerMetadata, OAuthTokenType, TokenSet};
use jacquard::types::string::{Datetime, Did, Handle};
use jacquard_identity::resolver::{
    DidDocResponse, IdentityError, IdentityResolver, ResolverOptions,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

const CHILD_TEST: &str = "kipclip::auth::lifecycle_tests::oauth_lifecycle_child";
const DID: &str = "did:plc:fixtureaccount";
const HANDLE: &str = "fixture.test";
const ID: &str = "fixture-oauth-state";
const NEW_ID: &str = "fixture-new-oauth-state";
const ACCESS: &str = "fixture-oauth-access";
const REFRESH: &str = "fixture-oauth-refresh";
const ROTATED: &str = "fixture-oauth-rotated";
const ISSUER: &str = "https://issuer.test";
const PDS: &str = "https://pds.test";

fn fixture() -> ClientSessionData<'static> {
    let did = Did::new_static(DID).unwrap();
    ClientSessionData {
        account_did: did.clone(),
        session_id: ID.into(),
        host_url: PDS.into(),
        authserver_url: ISSUER.into(),
        authserver_token_endpoint: "https://issuer.test/oauth/token".into(),
        authserver_revocation_endpoint: None,
        scopes: Scope::parse_multiple(OAUTH_SCOPE).unwrap(),
        dpop_data: DpopClientData {
            dpop_key: jacquard::oauth::utils::generate_key(&["ES256".into()]).unwrap(),
            dpop_authserver_nonce: "fixture-auth-nonce".into(),
            dpop_host_nonce: "fixture-host-nonce".into(),
        },
        token_set: TokenSet {
            iss: ISSUER.into(),
            sub: did,
            aud: PDS.into(),
            scope: Some(OAUTH_SCOPE.into()),
            refresh_token: Some(REFRESH.into()),
            access_token: ACCESS.into(),
            token_type: OAuthTokenType::DPoP,
            expires_at: Some(Datetime::new(
                (chrono::Utc::now() + chrono::TimeDelta::hours(1)).fixed_offset(),
            )),
        },
    }
}

fn info() -> SessionInfo {
    SessionInfo {
        did: DID.into(),
        handle: HANDLE.into(),
        session_id: ID.into(),
        auth_method: AuthMethod::OAuth,
    }
}

fn metadata() -> ClientData<'static> {
    ClientData {
        keyset: None,
        config: loopback_client_metadata(),
    }
}

#[derive(Default)]
struct MockOAuth {
    opts: ResolverOptions,
    pause_refresh: bool,
}

impl IdentityResolver for MockOAuth {
    fn options(&self) -> &ResolverOptions {
        &self.opts
    }
    async fn resolve_handle(
        &self,
        _: &Handle<'_>,
    ) -> std::result::Result<Did<'static>, IdentityError> {
        panic!("no identity/network fallback in OAuth lifecycle tests")
    }
    async fn resolve_did_doc(
        &self,
        _: &Did<'_>,
    ) -> std::result::Result<DidDocResponse, IdentityError> {
        panic!("no DID/network fallback in OAuth lifecycle tests")
    }
}

impl OAuthResolver for MockOAuth {
    async fn get_authorization_server_metadata(
        &self,
        issuer: &CowStr<'_>,
    ) -> std::result::Result<OAuthAuthorizationServerMetadata<'static>, ResolverError> {
        assert_eq!(
            Url::parse(issuer.as_str()).unwrap(),
            Url::parse(ISSUER).unwrap()
        );
        Ok(OAuthAuthorizationServerMetadata {
            issuer: ISSUER.into(),
            token_endpoint: "https://issuer.test/oauth/token".into(),
            authorization_endpoint: "https://issuer.test/authorize".into(),
            token_endpoint_auth_methods_supported: Some(vec!["none".into()]),
            dpop_signing_alg_values_supported: Some(vec!["ES256".into()]),
            ..Default::default()
        })
    }

    async fn verify_issuer(
        &self,
        _: &OAuthAuthorizationServerMetadata<'_>,
        did: &Did<'_>,
    ) -> std::result::Result<Url, ResolverError> {
        assert_eq!(did.as_str(), DID);
        Ok(Url::parse(PDS).unwrap())
    }
}

impl jacquard::oauth::dpop::DpopExt for MockOAuth {}

impl HttpClient for MockOAuth {
    type Error = std::convert::Infallible;
    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, Self::Error> {
        if request.uri().path() == "/xrpc/com.atproto.server.getSession" {
            assert_eq!(request.method(), http::Method::GET);
            assert!(request.headers().contains_key("dpop"));
            let auth = request.headers()["authorization"].to_str().unwrap();
            if auth == format!("DPoP {ACCESS}") {
                return Ok(http::Response::builder()
                    .status(401)
                    .header("www-authenticate", "DPoP error=\"invalid_token\"")
                    .body(Vec::new())
                    .unwrap());
            }
            assert_eq!(auth, format!("DPoP {ROTATED}"));
            return Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::to_vec(
                        &serde_json::json!({"did":DID,"handle":HANDLE,"active":true}),
                    )
                    .unwrap(),
                )
                .unwrap());
        }
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://issuer.test/oauth/token");
        assert!(request.headers().contains_key("dpop"));
        let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(request.body())
            .into_owned()
            .collect();
        let refreshing = form.get("grant_type").unwrap() == "refresh_token";
        if refreshing {
            assert_eq!(form.get("refresh_token").unwrap(), REFRESH);
            if self.pause_refresh {
                marker("REFRESH_HTTP");
                proceed();
            }
        } else {
            assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
            assert_eq!(form.get("code").unwrap(), "fixture-callback-code");
        }
        Ok(http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({
                    "access_token": if refreshing { ROTATED } else { ACCESS },
                    "refresh_token": if refreshing { ROTATED } else { REFRESH },
                    "token_type":"DPoP", "expires_in":3600, "sub":DID, "scope":OAUTH_SCOPE
                }))
                .unwrap(),
            )
            .unwrap())
    }
}

fn marker(text: &str) {
    println!("{text}");
    std::io::stdout().flush().unwrap();
}

fn proceed() {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "CONTINUE");
}

fn assert_lock_blocked(path: &Path) {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.with_file_name(".session.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock
    );
    marker("LOCK_BLOCKED");
}

fn assert_logged_out(path: &Path) {
    assert!(!path.exists(), "no orphan OAuth token store after logout");
    assert!(
        !path.with_file_name("whoami.json").exists(),
        "no active pointer after logout"
    );
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [".session.lock"]);
}

#[tokio::test]
async fn oauth_lifecycle_child() {
    let Ok(action) = std::env::var("KIP_OAUTH_TEST_ACTION") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("KIP_OAUTH_TEST_STORE").unwrap());
    assert!(
        path.starts_with(std::env::temp_dir()),
        "disposable test stores only"
    );
    match action.as_str() {
        "login" | "queued-login" => {
            let id = if action == "queued-login" {
                assert_lock_blocked(&path);
                NEW_ID
            } else {
                ID
            };
            let store = OAuthStore::login_at(&path).await.unwrap();
            let oauth = OAuthClient::new_from_resolver(store, MockOAuth::default(), metadata());
            let data = fixture();
            let state = AuthRequestData {
                state: id.into(),
                authserver_url: ISSUER.into(),
                account_did: Some(data.account_did),
                scopes: data.scopes,
                request_uri: "urn:fixture:par".into(),
                authserver_token_endpoint: "https://issuer.test/oauth/token".into(),
                authserver_revocation_endpoint: None,
                pkce_verifier: "fixture-pkce-verifier".into(),
                dpop_data: DpopReqData {
                    dpop_key: data.dpop_data.dpop_key,
                    dpop_authserver_nonce: Some("fixture-auth-nonce".into()),
                },
            };
            oauth
                .registry
                .store
                .save_auth_req_info(&state)
                .await
                .unwrap();
            marker("AUTH_STATE_STORED");
            proceed();
            // Exercise Jacquard's REAL callback/delete-state/create-session
            // sequence, with a completely in-memory authorization server.
            let session = oauth
                .callback(CallbackParams {
                    code: "fixture-callback-code".into(),
                    state: Some(id.into()),
                    iss: Some(ISSUER.into()),
                })
                .await
                .unwrap();
            marker("TOKENS_WRITTEN");
            proceed();
            assert_eq!(
                save_session_info(&session, HANDLE).await.unwrap(),
                SessionInfo {
                    session_id: id.into(),
                    ..info()
                }
            );
            drop(oauth); // Session must retain the transaction independently.
            marker("ACTIVE");
            proceed();
            session.refresh().await.unwrap(); // real Jacquard registry write
            let store = session.registry.store.clone();
            let mut data = session.data.read().await.clone().into_static();
            data.token_set.access_token = ROTATED.into();
            data.token_set.refresh_token = Some(ROTATED.into());
            drop(session); // Even a surviving store handle must keep the lock.
            store.upsert_session(data).await.unwrap();
            marker("STORE_ONLY");
            proceed();
            drop(store);
        }
        "refresh" | "implicit-refresh" | "restore-refresh" => {
            let store = OAuthStore::restore_at(&path, &info()).await.unwrap();
            let oauth = OAuthClient::new_from_resolver(
                store,
                MockOAuth {
                    pause_refresh: true,
                    ..Default::default()
                },
                metadata(),
            );
            let session;
            if action == "restore-refresh" {
                let mut data = oauth
                    .registry
                    .store
                    .get_session(&Did::new_static(DID).unwrap(), ID)
                    .await
                    .unwrap()
                    .unwrap()
                    .into_static();
                data.token_set.expires_at = None;
                oauth.registry.set(data).await.unwrap();
                marker("BEFORE_REFRESH");
                proceed();
                // Restore itself can perform HTTP refresh and two store writes.
                session = oauth
                    .restore(&Did::new_static(DID).unwrap(), ID)
                    .await
                    .unwrap();
                drop(oauth);
            } else {
                session = oauth
                    .restore(&Did::new_static(DID).unwrap(), ID)
                    .await
                    .unwrap();
                drop(oauth);
                let mut data = session.data.read().await.clone().into_static();
                data.token_set.expires_at = None;
                session.registry.set(data).await.unwrap();
                marker("BEFORE_REFRESH");
                proceed();
                if action == "implicit-refresh" {
                    let response = session
                        .send(jacquard::api::com_atproto::server::get_session::GetSession)
                        .await
                        .unwrap();
                    assert_eq!(response.status(), 200);
                } else {
                    session.refresh().await.unwrap();
                }
            }
            assert_eq!(
                session.data.read().await.token_set.access_token.as_str(),
                ROTATED
            );
            marker("REFRESHED");
            proceed();
            drop(session);
        }
        "queued-restore" => {
            assert_lock_blocked(&path);
            let store = OAuthStore::restore_at(&path, &info()).await.unwrap();
            let oauth = oauth_client_from_store(store);
            let session = oauth
                .restore(&Did::new_static(DID).unwrap(), ID)
                .await
                .unwrap();
            // Latest rotated tokens must be read AFTER obtaining the lock.
            assert_eq!(
                session.data.read().await.token_set.refresh_token.as_deref(),
                Some(ROTATED)
            );
            session.refresh().await.unwrap(); // unexpired, entirely offline
            marker("READ_LATEST");
            proceed();
        }
        "stale-restore" => {
            let cached = parse_session_info(
                &std::fs::read_to_string(path.with_file_name("whoami.json")).unwrap(),
            )
            .unwrap();
            marker("CACHED_INFO");
            proceed();
            assert!(OAuthStore::restore_at(&path, &cached).await.is_err());
        }
        "logout" => {
            assert_lock_blocked(&path);
            config::clear_sessions(path.parent().unwrap()).unwrap();
            assert_logged_out(&path);
            marker("LOGGED_OUT");
        }
        _ => panic!("invalid isolated OAuth lifecycle action"),
    }
    marker("DONE");
}

struct Worker {
    child: Child,
    lines: Receiver<String>,
}

impl Worker {
    fn spawn(path: &Path, action: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env_clear()
            .env("TMPDIR", std::env::temp_dir())
            .env("HOME", path.parent().unwrap())
            .env("KIP_OAUTH_TEST_STORE", path)
            .env("KIP_OAUTH_TEST_ACTION", action)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let reader = BufReader::new(child.stdout.take().unwrap());
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    fn expect(&mut self, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let line = self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    let mut detail = String::new();
                    if matches!(error, std::sync::mpsc::RecvTimeoutError::Disconnected) {
                        self.child.stderr.take().unwrap().read_to_string(&mut detail).unwrap();
                    }
                    panic!("OAuth helper did not reach {marker}; possible nested flock or lifecycle regression: {detail}")
                });
            if line.trim() == marker {
                return;
            }
        }
    }

    fn go(&mut self) {
        writeln!(self.child.stdin.as_mut().unwrap(), "CONTINUE").unwrap();
    }

    fn finish(&mut self) {
        self.expect("DONE");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let mut error = String::new();
                self.child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut error)
                    .unwrap();
                assert!(status.success(), "isolated OAuth helper failed: {error}");
                return;
            }
            assert!(Instant::now() < deadline, "OAuth helper did not terminate");
            std::thread::sleep(Duration::from_millis(5)); // watchdog only
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

async fn seed(path: &Path) {
    let oauth = oauth_client_at(path).await.unwrap();
    oauth.registry.set(fixture()).await.unwrap();
    let session = oauth
        .restore(&Did::new_static(DID).unwrap(), ID)
        .await
        .unwrap();
    save_session_info(&session, HANDLE).await.unwrap();
}

#[test]
fn oauth_login_and_surviving_token_store_cannot_reappear_after_logout() {
    for pause_before_token in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session.json");
        let mut login = Worker::spawn(&path, "login");
        login.expect("AUTH_STATE_STORED");
        let mut logout = if pause_before_token {
            let mut child = Worker::spawn(&path, "logout");
            child.expect("LOCK_BLOCKED");
            Some(child)
        } else {
            None
        };
        login.go();
        login.expect("TOKENS_WRITTEN");
        if logout.is_none() {
            let mut child = Worker::spawn(&path, "logout");
            child.expect("LOCK_BLOCKED");
            logout = Some(child);
        }
        let mut logout = logout.unwrap();
        login.go();
        login.expect("ACTIVE");
        login.go();
        login.expect("STORE_ONLY");
        assert!(path.with_file_name("whoami.json").exists());
        assert!(std::fs::read_to_string(&path).unwrap().contains(ROTATED));
        assert!(logout.child.try_wait().unwrap().is_none());
        login.go();
        login.finish();
        logout.expect("LOGGED_OUT");
        logout.finish();
        assert_logged_out(&path);
    }
}

#[tokio::test]
async fn oauth_refresh_write_in_flight_finishes_before_logout_removes_both_files() {
    for action in ["refresh", "implicit-refresh", "restore-refresh"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session.json");
        seed(&path).await;
        let inode = path
            .with_file_name(".session.lock")
            .metadata()
            .unwrap()
            .ino();
        let mut refresh = Worker::spawn(&path, action);
        refresh.expect("BEFORE_REFRESH");
        refresh.go();
        refresh.expect("REFRESH_HTTP");
        let mut logout = Worker::spawn(&path, "logout");
        logout.expect("LOCK_BLOCKED");
        refresh.go();
        refresh.expect("REFRESHED");
        assert!(std::fs::read_to_string(&path).unwrap().contains(ROTATED));
        assert!(logout.child.try_wait().unwrap().is_none());
        refresh.go();
        refresh.finish();
        logout.expect("LOGGED_OUT");
        logout.finish();
        assert_logged_out(&path);
        assert_eq!(
            path.with_file_name(".session.lock")
                .metadata()
                .unwrap()
                .ino(),
            inode
        );
    }
}

#[tokio::test]
async fn concurrent_oauth_restore_and_refresh_read_latest_tokens_only_after_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.json");
    seed(&path).await;
    let mut refresh = Worker::spawn(&path, "refresh");
    refresh.expect("BEFORE_REFRESH");
    refresh.go();
    refresh.expect("REFRESH_HTTP");
    let mut restore = Worker::spawn(&path, "queued-restore");
    restore.expect("LOCK_BLOCKED");
    refresh.go();
    refresh.expect("REFRESHED");
    refresh.go();
    refresh.finish();
    restore.expect("READ_LATEST");
    let mut logout = Worker::spawn(&path, "logout");
    logout.expect("LOCK_BLOCKED");
    restore.go();
    restore.finish();
    logout.expect("LOGGED_OUT");
    logout.finish();
    assert_logged_out(&path);
}

#[tokio::test]
async fn oauth_login_waits_for_in_flight_refresh_before_token_write_and_activation() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.json");
    seed(&path).await;
    let mut refresh = Worker::spawn(&path, "refresh");
    refresh.expect("BEFORE_REFRESH");
    refresh.go();
    refresh.expect("REFRESH_HTTP");
    let mut login = Worker::spawn(&path, "queued-login");
    login.expect("LOCK_BLOCKED");
    refresh.go();
    refresh.expect("REFRESHED");
    refresh.go();
    refresh.finish();
    login.expect("AUTH_STATE_STORED");
    login.go();
    login.expect("TOKENS_WRITTEN");
    login.go();
    login.expect("ACTIVE");
    let active =
        parse_session_info(&std::fs::read_to_string(path.with_file_name("whoami.json")).unwrap())
            .unwrap();
    assert_eq!(active.session_id, NEW_ID);
    let mut logout = Worker::spawn(&path, "logout");
    logout.expect("LOCK_BLOCKED");
    login.go();
    login.expect("STORE_ONLY");
    login.go();
    login.finish();
    logout.expect("LOGGED_OUT");
    logout.finish();
    assert_logged_out(&path);
}

#[tokio::test]
async fn oauth_restore_cached_before_logout_or_new_login_never_recreates_or_replaces_files() {
    for replacement in ["logout", "app-login", "oauth-login", "missing-tokens"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session.json");
        seed(&path).await;
        let mut stale = Worker::spawn(&path, "stale-restore");
        stale.expect("CACHED_INFO");
        if replacement == "logout" {
            config::clear_sessions(root.path()).unwrap();
        } else if replacement == "missing-tokens" {
            std::fs::remove_file(&path).unwrap();
        } else {
            let mut replacement_info = info();
            if replacement == "app-login" {
                replacement_info.auth_method = AuthMethod::AppPassword;
            } else {
                replacement_info.session_id = "new-oauth-login".into();
            }
            config::write_private_file(
                &path.with_file_name("whoami.json"),
                &serde_json::to_vec(&replacement_info).unwrap(),
            )
            .unwrap();
        }
        let tokens_before = std::fs::read(&path).ok();
        let pointer_before = std::fs::read(path.with_file_name("whoami.json")).ok();
        stale.go();
        stale.finish();
        assert_eq!(std::fs::read(&path).ok(), tokens_before);
        assert_eq!(
            std::fs::read(path.with_file_name("whoami.json")).ok(),
            pointer_before
        );
        config::clear_sessions(root.path()).unwrap();
        assert_logged_out(&path);
    }
}
