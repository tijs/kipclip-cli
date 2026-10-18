//! Real Jacquard PAR/callback/FileAuthStore, synthetic HTTP and terminal I/O.
//! No browser, DNS, OAuth/PDS connection or callback listener is used.

use super::*;
use jacquard::http_client::HttpClient;
use jacquard::oauth::resolver::ResolverError;
use jacquard::oauth::types::OAuthAuthorizationServerMetadata;
use jacquard::types::did_doc::DidDocument;
use jacquard::types::string::{Did, Handle};
use jacquard_identity::resolver::{
    DidDocResponse, IdentityError, IdentityResolver, ResolverOptions,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

const DID: &str = "did:plc:fixtureaccount";
const HANDLE: &str = "fixture.test";
const ISSUER: &str = "https://issuer.test";
const REDIRECT: &str = "http://127.0.0.1:4000/oauth/callback";
const CODE: &str = "fixture-private-code+/?=";
const ACCESS: &str = "fixture-private-access";
const REFRESH: &str = "fixture-private-refresh";
const PRIVATE: &str = "fixture-private-detail";

#[derive(Default)]
struct MockOAuth {
    opts: ResolverOptions,
    requests: Mutex<Vec<http::Request<Vec<u8>>>>,
    fail_start: bool,
    fail_token: bool,
}

fn metadata() -> OAuthAuthorizationServerMetadata<'static> {
    OAuthAuthorizationServerMetadata {
        issuer: ISSUER.into(),
        authorization_endpoint: "https://issuer.test/authorize".into(),
        token_endpoint: "https://issuer.test/oauth/token".into(),
        pushed_authorization_request_endpoint: Some("https://issuer.test/oauth/par".into()),
        authorization_response_iss_parameter_supported: Some(true),
        token_endpoint_auth_methods_supported: Some(vec!["none".into()]),
        dpop_signing_alg_values_supported: Some(vec!["ES256".into()]),
        ..Default::default()
    }
}

impl IdentityResolver for MockOAuth {
    fn options(&self) -> &ResolverOptions {
        &self.opts
    }

    async fn resolve_handle(
        &self,
        _: &Handle<'_>,
    ) -> std::result::Result<Did<'static>, IdentityError> {
        panic!("no identity/network fallback in manual OAuth tests")
    }

    async fn resolve_did_doc(
        &self,
        _: &Did<'_>,
    ) -> std::result::Result<DidDocResponse, IdentityError> {
        panic!("no DID/network fallback in manual OAuth tests")
    }
}

impl OAuthResolver for MockOAuth {
    async fn resolve_oauth(
        &self,
        input: &str,
    ) -> std::result::Result<
        (
            OAuthAuthorizationServerMetadata<'static>,
            Option<DidDocument<'static>>,
        ),
        ResolverError,
    > {
        assert_eq!(input, HANDLE);
        if self.fail_start {
            return Err(ResolverError::transport(io::Error::other(PRIVATE)));
        }
        Ok((metadata(), None))
    }

    async fn get_authorization_server_metadata(
        &self,
        issuer: &CowStr<'_>,
    ) -> std::result::Result<OAuthAuthorizationServerMetadata<'static>, ResolverError> {
        assert_eq!(
            Url::parse(issuer.as_str()).unwrap(),
            Url::parse(ISSUER).unwrap()
        );
        Ok(metadata())
    }

    async fn verify_issuer(
        &self,
        server: &OAuthAuthorizationServerMetadata<'_>,
        did: &Did<'_>,
    ) -> std::result::Result<Url, ResolverError> {
        assert_eq!(server.issuer.as_str(), ISSUER);
        assert_eq!(did.as_str(), DID);
        Ok(Url::parse("https://pds.test").unwrap())
    }
}

impl DpopExt for MockOAuth {}

fn form(request: &http::Request<Vec<u8>>) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.body())
        .into_owned()
        .collect()
}

impl HttpClient for MockOAuth {
    type Error = std::convert::Infallible;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, Self::Error> {
        assert_eq!(request.method(), http::Method::POST);
        assert!(request.headers().contains_key("dpop"));
        let params = form(&request);
        assert_eq!(params["redirect_uri"], REDIRECT);
        assert_eq!(
            params["client_id"],
            loopback_client_metadata().client_id.as_str()
        );
        let (status, body) = match request.uri().to_string().as_str() {
            "https://issuer.test/oauth/par" => {
                assert_eq!(params["scope"], "atproto transition:generic");
                assert_eq!(params["response_type"], "code");
                assert_eq!(params["code_challenge_method"], "S256");
                assert!(!params["code_challenge"].is_empty());
                assert!(!params["state"].is_empty());
                (
                    201,
                    serde_json::json!({"request_uri":"urn:fixture:par", "expires_in":300}),
                )
            }
            "https://issuer.test/oauth/token" => {
                assert_eq!(params["grant_type"], "authorization_code");
                assert_eq!(params["code"], CODE);
                assert!(!params["code_verifier"].is_empty());
                if self.fail_token {
                    (
                        400,
                        serde_json::json!({"error":"invalid_grant", "error_description":PRIVATE}),
                    )
                } else {
                    (
                        200,
                        serde_json::json!({
                            "access_token":ACCESS, "refresh_token":REFRESH, "token_type":"DPoP",
                            "expires_in":3600, "sub":DID, "scope":"atproto transition:generic"
                        }),
                    )
                }
            }
            _ => panic!("unexpected HTTP request; no network fallback is allowed"),
        };
        self.requests.lock().unwrap().push(request);
        Ok(http::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("dpop-nonce", "fixture-auth-nonce")
            .body(serde_json::to_vec(&body).unwrap())
            .unwrap())
    }
}

async fn client(path: &Path, mock: MockOAuth) -> OAuthClient<MockOAuth, OAuthStore> {
    OAuthClient::new_from_resolver(
        OAuthStore::login_at(path).await.unwrap(),
        mock,
        ClientData {
            keyset: None,
            config: loopback_client_metadata(),
        },
    )
}

fn json_at(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn par(oauth: &OAuthClient<MockOAuth, OAuthStore>) -> HashMap<String, String> {
    let requests = oauth.client.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "only PAR may precede the pasted callback"
    );
    form(&requests[0])
}

fn callback(state: &str, issuer: Option<&str>) -> String {
    let mut url = Url::parse(REDIRECT).unwrap();
    url.query_pairs_mut()
        .append_pair("code", CODE)
        .append_pair("state", state);
    if let Some(issuer) = issuer {
        url.query_pairs_mut().append_pair("iss", issuer);
    }
    url.into()
}

fn assert_private(text: &str) {
    for sentinel in [CODE, ACCESS, REFRESH, PRIVATE] {
        assert!(
            !text.contains(sentinel),
            "must not echo private callback/token/error material"
        );
    }
}

fn assert_callback_port_unavailable() {
    // A bind-only socket is not a listener. The actual Jacquard helper's
    // wildcard bind must be unavailable throughout this test's login flows.
    let probe = tokio::net::TcpSocket::new_v4().unwrap();
    let error = probe
        .bind(([0, 0, 0, 0], LOOPBACK_PORT).into())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
}

#[tokio::test]
async fn default_headless_and_browser_failure_share_callback_without_a_listener() {
    // Reserve the callback port WITHOUT listening or accepting any connections.
    // An already occupied port is also fine: manual login must not need it.
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    if let Err(error) = reserved.bind(([127, 0, 0, 1], LOOPBACK_PORT).into()) {
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }
    assert_callback_port_unavailable();
    for (headless, browser_fails) in [(false, false), (true, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session.json");
        let oauth = client(&path, MockOAuth::default()).await;
        let events = RefCell::new(Vec::new());
        let expected = RefCell::new(None);
        let mut output = Vec::new();
        let info = login_with_oauth(
            &oauth,
            HANDLE,
            headless,
            |authorization_url| {
                assert!(!headless, "headless must never try opening a browser");
                let url = Url::parse(authorization_url).unwrap();
                assert_eq!(url.host_str(), Some("issuer.test"));
                assert_eq!(url.path(), "/authorize");
                let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(params["request_uri"], "urn:fixture:par");
                assert_eq!(
                    params["client_id"],
                    loopback_client_metadata().client_id.as_str()
                );
                events.borrow_mut().push("open");
                if browser_fails {
                    Err(io::Error::other(PRIVATE))
                } else {
                    Ok(())
                }
            },
            |prompt| {
                assert_eq!(prompt, "Callback URL: ");
                events.borrow_mut().push("paste");
                assert_callback_port_unavailable();
                let params = par(&oauth);
                let state = params["state"].clone();
                let stored = json_at(&path);
                let request = &stored[format!("authreq_{state}")]["OAuthState"];
                assert_eq!(request["state"], state);
                assert_eq!(
                    request["scopes"],
                    serde_json::json!(["atproto", "transition:generic"])
                );
                assert!(request.get("dpop_key").is_some());
                assert!(!path.with_file_name("whoami.json").exists());
                *expected.borrow_mut() = Some((
                    state.clone(),
                    request["pkce_verifier"].clone(),
                    request["dpop_key"].clone(),
                ));
                // The production hidden reader's result is trimmed, then parsed.
                Ok(format!(" \n{}\t ", callback(&state, Some(ISSUER))))
            },
            &mut output,
        )
        .await
        .unwrap();
        assert_eq!(
            *events.borrow(),
            if headless {
                vec!["paste"]
            } else {
                vec!["open", "paste"]
            }
        );
        let (state, verifier, key) = expected.into_inner().unwrap();
        assert_eq!(
            info,
            SessionInfo {
                did: DID.into(),
                handle: HANDLE.into(),
                session_id: state.clone(),
                auth_method: AuthMethod::OAuth,
            }
        );
        assert_eq!(
            json_at(&path.with_file_name("whoami.json")),
            serde_json::to_value(&info).unwrap()
        );
        let tokens = json_at(&path);
        assert_eq!(
            tokens.as_object().unwrap().len(),
            1,
            "callback must consume its authorization state"
        );
        let saved = &tokens[format!("{DID}_{state}")]["OAuth"];
        assert_eq!(saved["access_token"], ACCESS);
        assert_eq!(saved["refresh_token"], REFRESH);
        assert_eq!(saved["dpop_key"], key);
        let requests = oauth.client.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "exactly one PAR and one token exchange");
        assert_eq!(
            serde_json::to_value(&form(&requests[1])["code_verifier"]).unwrap(),
            verifier
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("https://issuer.test/authorize?"));
        assert!(output.contains("connection-refused") && output.contains("hidden prompt"));
        assert!(output.contains("kip starts no callback server"));
        assert_eq!(output.contains("Could not open a browser"), browser_fails);
        assert_private(&output);
        assert_callback_port_unavailable();
    }
}

#[tokio::test]
async fn both_modes_validate_pasted_urls_before_consuming_state_or_exchanging_tokens() {
    for headless in [false, true] {
        for invalid in [
            "not a URL",
            "https://127.0.0.1:4000/oauth/callback?code=x&state=y",
            "http://localhost:4000/oauth/callback?code=x&state=y",
            "http://192.168.1.2:4000/oauth/callback?code=x&state=y",
            "http://127.0.0.1/oauth/callback?code=x&state=y",
            "http://127.0.0.1:4001/oauth/callback?code=x&state=y",
            "http://127.0.0.1:4000/wrong?code=x&state=y",
            "http://127.0.0.1:4000/oauth/callback?state=y",
            "http://127.0.0.1:4000/oauth/callback?code=&state=y",
            "http://127.0.0.1:4000/oauth/callback?code=x",
            "http://127.0.0.1:4000/oauth/callback?code=x&state=",
            "http://127.0.0.1:4000/oauth/callback?code=x&code=fixture-private-detail&state=y",
            "http://127.0.0.1:4000/oauth/callback?code=x&state=y&sta%74e=fixture-private-detail",
            "http://127.0.0.1:4000/oauth/callback?code=x&state=y&iss=x&iss=fixture-private-detail",
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("session.json");
            let oauth = client(&path, MockOAuth::default()).await;
            let mut output = Vec::new();
            let error = login_with_oauth(
                &oauth,
                HANDLE,
                headless,
                |_| Ok(()),
                |_| Ok(invalid.into()),
                &mut output,
            )
            .await
            .unwrap_err();
            assert_private(&error.to_string());
            assert_private(&format!("{error:?}"));
            let params = par(&oauth);
            assert!(
                json_at(&path)
                    .get(format!("authreq_{}", params["state"]))
                    .is_some(),
                "local validation must precede Jacquard's state deletion"
            );
            assert!(!path.with_file_name("whoami.json").exists());
        }
    }
}

#[tokio::test]
async fn both_modes_retain_sdk_state_and_issuer_validation_before_token_exchange() {
    for headless in [false, true] {
        for rejection in ["wrong-state", "wrong-issuer", "missing-issuer"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("session.json");
            let oauth = client(&path, MockOAuth::default()).await;
            let mut output = Vec::new();
            let error = login_with_oauth(
                &oauth,
                HANDLE,
                headless,
                |_| Ok(()),
                |_| {
                    let params = par(&oauth);
                    Ok(match rejection {
                        "wrong-state" => callback(PRIVATE, Some(ISSUER)),
                        "wrong-issuer" => callback(
                            &params["state"],
                            Some("https://fixture-private-detail.test"),
                        ),
                        _ => callback(&params["state"], None),
                    })
                },
                &mut output,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("KIP_OAUTH_LOGIN_FAILED"));
            assert_private(&format!("{error:?}"));
            par(&oauth); // No token exchange, even for syntactically valid URLs.
            assert!(!path.with_file_name("whoami.json").exists());
        }
    }
}

#[tokio::test]
async fn failed_token_exchange_keeps_active_identity_and_redacts_callback_and_server_details() {
    for headless in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session.json");
        let oauth = client(
            &path,
            MockOAuth {
                fail_token: true,
                ..Default::default()
            },
        )
        .await;
        let previous = SessionInfo {
            did: DID.into(),
            handle: HANDLE.into(),
            session_id: "previous-oauth-login".into(),
            auth_method: AuthMethod::OAuth,
        };
        oauth.registry.store.activate(&previous).unwrap();
        let before = std::fs::read(path.with_file_name("whoami.json")).unwrap();
        let mut output = Vec::new();
        let error = login_with_oauth(
            &oauth,
            HANDLE,
            headless,
            |_| Ok(()),
            |_| Ok(callback(&par(&oauth)["state"], Some(ISSUER))),
            &mut output,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("KIP_OAUTH_LOGIN_FAILED"));
        assert_private(&format!("{error:?}"));
        assert_private(&String::from_utf8(output).unwrap());
        assert_eq!(oauth.client.requests.lock().unwrap().len(), 2);
        assert_eq!(json_at(&path), serde_json::json!({}));
        assert_eq!(
            std::fs::read(path.with_file_name("whoami.json")).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn start_and_hidden_input_failures_do_not_exchange_tokens_or_activate_identity() {
    for headless in [false, true] {
        for fail_start in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("session.json");
            let oauth = client(
                &path,
                MockOAuth {
                    fail_start,
                    ..Default::default()
                },
            )
            .await;
            let mut output = Vec::new();
            let error = login_with_oauth(
                &oauth,
                HANDLE,
                headless,
                |_| {
                    assert!(!fail_start && !headless);
                    Ok(())
                },
                |_| {
                    assert!(!fail_start);
                    Err(io::Error::other(PRIVATE))
                },
                &mut output,
            )
            .await
            .unwrap_err();
            assert_eq!(
                oauth.client.requests.lock().unwrap().len(),
                usize::from(!fail_start)
            );
            assert!(!path.with_file_name("whoami.json").exists());
            assert_private(&format!("{error:?}"));
            assert_private(&String::from_utf8(output).unwrap());
            assert!(error.to_string().contains(if fail_start {
                "KIP_OAUTH_LOGIN_FAILED"
            } else {
                "Could not read the hidden callback URL"
            }));
        }
    }
}

#[test]
fn metadata_preserves_exact_redirect_and_client_id_scopes() {
    let metadata = loopback_client_metadata();
    assert_eq!(metadata.redirect_uris, [Url::parse(REDIRECT).unwrap()]);
    let query: Vec<_> = metadata.client_id.query_pairs().into_owned().collect();
    assert_eq!(
        query,
        [
            ("redirect_uri".into(), REDIRECT.into()),
            ("scope".into(), "atproto transition:generic".into()),
        ]
    );
}

#[test]
fn cli_login_sources_cannot_start_a_callback_listener_or_use_visible_input() {
    for source in [
        include_str!("../auth.rs"),
        include_str!("oauth_store.rs"),
        include_str!("../../commands/login.rs"),
        include_str!("../../main.rs"),
    ] {
        for forbidden in [
            "login_with_local_server",
            "LoopbackConfig",
            "TcpListener",
            "TcpSocket",
            "Server::",
        ] {
            assert!(
                !source.contains(forbidden),
                "CLI OAuth must not start a callback listener"
            );
        }
    }
    assert!(include_str!("../auth.rs").contains("rpassword::prompt_password"));
    assert!(include_str!("../../commands/login.rs").contains("auth::login(handle, headless)"));
}
