//! All HTTP and identity operations are in-memory trait mocks. No sockets, DNS,
//! vault access, real credentials, or real user configuration are used.

#[path = "review_tests.rs"]
mod review;

use super::*;
use std::collections::VecDeque;

use std::sync::Mutex;

use jacquard::types::string::Did;
use jacquard_identity::resolver::{DidDocResponse, IdentityError, ResolverOptions};
use serde_json::{Value, json};

use crate::kipclip::auth::Session;
use crate::kipclip::pds::PdsClient;
use crate::kipclip::types::BOOKMARK_COLLECTION;

// Synthetic sentinels, deliberately not usable account credentials/JWTs.
const PASSWORD: &str = "fixture-only-not-a-credential";
const PRIVATE: &str = "fixture-private-detail";
const DID: &str = "did:plc:fixtureaccount";
const HANDLE: &str = "tijs.org";
const PDS: &str = "https://account-pds.test";
const ACCESS: &str = "fixture.access.initial";
const REFRESH: &str = "fixture.refresh.initial";
const ACCESS_NEXT: &str = "fixture.access.rotated";
const REFRESH_NEXT: &str = "fixture.refresh.rotated";

#[tokio::test]
async fn cached_save_verifies_exact_records_without_scanning_or_fetching_pages() {
    use crate::kipclip::types::{ANNOTATION_COLLECTION, UrlMetadata};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let client = pds(&info, &path, http.clone());
    let uri = format!("at://{DID}/{BOOKMARK_COLLECTION}/fixturekey");
    let annotation_uri = format!("at://{DID}/{ANNOTATION_COLLECTION}/fixturekey");
    let cid = "bafyreiclbzdovdyoyzymb7t3getdeam3hgwqxszgth5ukj6o3tkoftthei";
    http.reply(200, json!({"uri":uri,"cid":cid}));
    http.reply(200, json!({"uri":annotation_uri,"cid":cid}));
    http.reply(200, json!({"uri":uri,"cid":cid,"value":{"subject":"https://article.test/", "createdAt":"2026-10-24T00:00:00Z", "tags":["toread"]}}));
    http.reply(200, json!({"uri":annotation_uri,"cid":cid,"value":{"subject":uri,"createdAt":"2026-10-24T00:00:00Z","title":"Cached title"}}));
    let metadata = UrlMetadata {
        title: Some("Cached title".into()),
        description: None,
        image: None,
        favicon: None,
    };
    let saved = crate::commands::add::save_verified(
        &client,
        "https://article.test/",
        &["toread".into()],
        metadata,
    )
    .await
    .unwrap();
    assert_eq!(saved.uri, uri);
    assert_eq!(saved.tags, ["toread"]);
    http.assert_calls(&[
        ("POST", "com.atproto.server.createSession", None),
        ("POST", "com.atproto.repo.createRecord", Some(ACCESS)),
        ("POST", "com.atproto.repo.createRecord", Some(ACCESS)),
        ("GET", "com.atproto.repo.getRecord", Some(ACCESS)),
        ("GET", "com.atproto.repo.getRecord", Some(ACCESS)),
    ]);
    let requests = http.requests.lock().unwrap();
    let annotation: Value = serde_json::from_slice(requests[2].body()).unwrap();
    assert_eq!(annotation["record"]["title"], "Cached title");
    for req in &requests[3..] {
        assert!(req.uri().query().unwrap().contains("rkey=fixturekey"));
    }
}

#[tokio::test]
async fn cached_save_rejects_wrong_url_missing_tag_and_wrong_annotation() {
    use crate::kipclip::types::{ANNOTATION_COLLECTION, UrlMetadata};
    for failure in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let client = pds(&info, &path, http.clone());
        let uri = format!("at://{DID}/{BOOKMARK_COLLECTION}/fixturekey");
        let annotation_uri = format!("at://{DID}/{ANNOTATION_COLLECTION}/fixturekey");
        let cid = "bafyreiclbzdovdyoyzymb7t3getdeam3hgwqxszgth5ukj6o3tkoftthei";
        http.reply(200, json!({"uri":uri,"cid":cid}));
        if failure == 3 {
            http.reply(
                500,
                json!({"error":"InternalServerError","message":PRIVATE}),
            );
        } else {
            http.reply(200, json!({"uri":annotation_uri,"cid":cid}));
            http.reply(200, json!({"uri":uri,"cid":cid,"value":{"subject":if failure==0 {"https://wrong.test/"} else {"https://article.test/"}, "createdAt":"2026-10-24T00:00:00Z", "tags":if failure==1 {json!([])} else {json!(["toread"])}}}));
            http.reply(200, json!({"uri":annotation_uri,"cid":cid,"value":{"subject":if failure==2 {"at://did:plc:other/com.kipclip.annotation/other"} else {&uri},"createdAt":"2026-10-24T00:00:00Z"}}));
        }
        let metadata = UrlMetadata {
            title: None,
            description: None,
            image: None,
            favicon: None,
        };
        let error = crate::commands::add::save_verified(
            &client,
            "https://article.test/",
            &["toread".into()],
            metadata,
        )
        .await
        .unwrap_err();
        assert_sanitized(&error);
        assert_eq!(
            http.requests.lock().unwrap().len(),
            if failure == 3 { 3 } else { 5 }
        );
    }
}

type MockReply = std::io::Result<http::Response<Vec<u8>>>;

#[derive(Default, Clone)]
struct MockHttp {
    replies: Arc<Mutex<VecDeque<MockReply>>>,
    requests: Arc<Mutex<Vec<http::Request<Vec<u8>>>>>,
}

impl MockHttp {
    fn reply(&self, status: u16, value: Value) {
        self.raw(status, serde_json::to_vec(&value).unwrap());
    }

    fn raw(&self, status: u16, bytes: Vec<u8>) {
        self.raw_headers(status, bytes, &[]);
    }

    fn raw_headers(&self, status: u16, bytes: Vec<u8>, headers: &[(&str, &str)]) {
        let mut response = http::Response::builder()
            .status(status)
            .header("content-type", "application/json");
        for (name, value) in headers {
            response = response.header(*name, *value);
        }
        self.replies
            .lock()
            .unwrap()
            .push_back(Ok(response.body(bytes).unwrap()));
    }

    fn transport_failure(&self) {
        self.replies
            .lock()
            .unwrap()
            .push_back(Err(std::io::Error::other(format!(
                "{PRIVATE} {PASSWORD} {ACCESS} {REFRESH} {HANDLE} {DID}"
            ))));
    }

    fn assert_calls(&self, expected: &[(&str, &str, Option<&str>)]) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), expected.len(), "unexpected request count");
        assert!(
            self.replies.lock().unwrap().is_empty(),
            "unused mock responses"
        );
        for (request, (method, nsid, auth)) in requests.iter().zip(expected) {
            assert!(request.method().as_str() == *method, "wrong HTTP method");
            let url = Url::parse(&request.uri().to_string()).unwrap();
            assert!(
                url.origin().ascii_serialization() == PDS,
                "must use identity-discovered PDS"
            );
            assert!(url.path() == format!("/xrpc/{nsid}"), "wrong XRPC endpoint");
            assert!(
                !request.uri().to_string().contains(PASSWORD),
                "password in URL"
            );
            let actual = request
                .headers()
                .get("authorization")
                .map(|h| h.to_str().unwrap());
            let expected = auth.map(|token| format!("Bearer {token}"));
            assert!(actual == expected.as_deref(), "wrong bearer token");
            if *nsid != "com.atproto.server.createSession" {
                assert!(
                    !String::from_utf8_lossy(request.body()).contains(PASSWORD),
                    "password reused"
                );
            }
        }
    }
}

impl HttpClient for MockHttp {
    type Error = std::io::Error;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::io::Result<http::Response<Vec<u8>>> {
        self.requests.lock().unwrap().push(request);
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected HTTP request (no network fallback)")
    }
}

struct MockResolver {
    doc: Value,
    opts: ResolverOptions,
}

impl Default for MockResolver {
    fn default() -> Self {
        Self {
            opts: Default::default(),
            doc: json!({
                "id": DID,
                "alsoKnownAs": [format!("at://{HANDLE}")],
                "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": PDS}]
            }),
        }
    }
}

impl IdentityResolver for MockResolver {
    fn options(&self) -> &ResolverOptions {
        &self.opts
    }

    async fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> std::result::Result<Did<'static>, IdentityError> {
        assert!(
            handle.as_str() == HANDLE,
            "must resolve the explicitly requested handle"
        );
        Ok(Did::new_static(DID).unwrap())
    }

    async fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> std::result::Result<DidDocResponse, IdentityError> {
        assert!(did.as_str() == DID, "must resolve the same DID");
        Ok(DidDocResponse {
            buffer: serde_json::to_vec(&self.doc).unwrap().into(),
            status: http::StatusCode::OK,
            requested: Some(did.clone().into_static()),
        })
    }
}

fn body(access: &str, refresh: &str) -> Value {
    json!({"did": DID, "handle": HANDLE, "active": true,
        "accessJwt": access, "refreshJwt": refresh,
        "email": PRIVATE, "didDoc": {"private": PRIVATE}, "password": PASSWORD})
}

fn password() -> AppPassword {
    password_from_env_with("BLUESKY_PASSWD", |_| Ok(PASSWORD.to_string())).unwrap()
}

async fn login_fixture(path: &Path, http: &MockHttp) -> SessionInfo {
    http.reply(200, body(ACCESS, REFRESH));
    login_with(
        &MockResolver::default(),
        http,
        &requested_handle(HANDLE).unwrap(),
        password(),
        path,
    )
    .await
    .unwrap()
}

fn pds(info: &SessionInfo, path: &Path, http: MockHttp) -> PdsClient<MockHttp> {
    let session = restore_with(info, path, http).unwrap();
    PdsClient::new(Session::AppPassword(Box::new(session)), &info.did).unwrap()
}

fn assert_sanitized(report: &miette::Report) {
    for text in [report.to_string(), format!("{report:?}")] {
        for private in [
            PASSWORD,
            PRIVATE,
            ACCESS,
            REFRESH,
            ACCESS_NEXT,
            REFRESH_NEXT,
            DID,
            HANDLE,
        ] {
            assert!(
                !text.contains(private),
                "diagnostic leaked private material"
            );
        }
    }
}

fn assert_minimal_store(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    for forbidden in [PASSWORD, PRIVATE, "BLUESKY_PASSWD", "email", "didDoc"] {
        assert!(!text.contains(forbidden), "forbidden material persisted");
    }
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let keys: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "did",
            "handle",
            "session_id",
            "auth_method",
            "pds",
            "access_jwt",
            "refresh_jwt",
            "generation"
        ]
        .into_iter()
        .collect()
    );
    let info: SessionInfo = serde_json::from_slice(&bytes).unwrap();
    let public = serde_json::to_string(&info).unwrap();
    assert!(
        !public.contains(ACCESS) && !public.contains(REFRESH),
        "whoami must not expose tokens"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            path.parent()
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        2,
        "only session and persistent empty interprocess lock; no password/temp files"
    );
}

#[test]
fn arbitrary_caller_selected_env_name_is_the_only_name_read() {
    for name in [
        "CUSTOM_LOGIN_SECRET",
        "_vendorAppPassword7",
        "lowercase_key",
    ] {
        let mut reads = Vec::new();
        let password = password_from_env_with(name, |selected| {
            reads.push(selected.to_owned());
            assert_eq!(
                selected, name,
                "must not substitute a built-in/vault key name"
            );
            Ok(PASSWORD.to_string())
        })
        .unwrap();
        assert_eq!(reads, [name]);
        assert!(
            password.0.as_str() == PASSWORD,
            "must not alter the selected variable's value"
        );
    }
}

#[test]
fn env_names_missing_empty_invalid_and_nonunicode_are_sanitized() {
    for name in [
        "",
        "1BAD",
        "BAD=NAME",
        "BAD-NAME",
        "BAD\nNAME",
        "BAD\0NAME",
        "nonascii_é",
    ] {
        let error = password_from_env_with(name, |_| panic!("invalid name must not be read"))
            .err()
            .expect("invalid variable name");
        assert_sanitized(&error);
        assert!(error.to_string().contains("KIP_APP_PASSWORD_ENV"));
    }
    let missing = password_from_env_with("BLUESKY_PASSWD", |_| Err(VarError::NotPresent))
        .err()
        .unwrap();
    assert_sanitized(&missing);
    assert!(
        missing
            .to_string()
            .contains("not set in this login process")
    );
    let empty = password_from_env_with("CUSTOM_LOGIN_SECRET", |_| Ok(String::new()))
        .err()
        .unwrap();
    assert!(empty.to_string().contains("is empty"));
    for value in ["", " ", "\n", "foo\nbar", "foo\0bar", "foo\tbar"] {
        let error = password_from_env_with("BLUESKY_PASSWD", |_| Ok(value.into()))
            .err()
            .expect("invalid value");
        assert_sanitized(&error);
    }
    let error = password_from_env_with("BLUESKY_PASSWD", |_| Ok("x".repeat(1025)))
        .err()
        .unwrap();
    assert_sanitized(&error);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let error = password_from_env_with("BLUESKY_PASSWD", |_| {
            Err(VarError::NotUnicode(std::ffi::OsString::from_vec(vec![
                0xff,
            ])))
        })
        .err()
        .unwrap();
        assert_sanitized(&error);
    }
}

#[test]
fn requested_identity_is_never_silently_repaired() {
    for handle in [
        "@tijs.org",
        "at://tijs.org",
        "tijs.org ",
        "tijs.org\n",
        "handle.invalid",
        "did:plc:fixtureaccount",
        "fixture-private-detail",
    ] {
        let error = requested_handle(handle).expect_err("invalid bare handle");
        assert_sanitized(&error);
    }
}

#[tokio::test]
async fn creates_at_correct_pds_and_persists_only_verified_session_privately() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config/whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    assert_eq!(info.auth_method, AuthMethod::AppPassword);
    assert_minimal_store(&path);
    let requests = http.requests.lock().unwrap();
    let input: Value = serde_json::from_slice(requests[0].body()).unwrap();
    assert!(input["identifier"] == HANDLE, "must use requested identity");
    assert!(
        input["password"] == PASSWORD,
        "must use same-process password, unchanged"
    );
    assert_eq!(input["allowTakendown"], false);
    assert!(input.get("authFactorToken").is_none());
    drop(requests);
    http.assert_calls(&[("POST", "com.atproto.server.createSession", None)]);
}

#[tokio::test]
async fn exact_create_account_mismatches_never_write_or_replace_oauth() {
    for (did, handle) in [
        ("did:plc:someoneelse", HANDLE),
        (DID, "other.org"),
        (DID, "tijs.org.evil.test"),
        (DID, "Tijs.org"),
        (DID, "@tijs.org"),
        (DID, "at://tijs.org"),
    ] {
        for existing in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("config/whoami.json");
            let previous = br#"{"did":"did:plc:oldfixture","handle":"old.test","session_id":"existing-oauth"}"#;
            if existing {
                config::write_private_file(&path, previous).unwrap();
            }
            let http = MockHttp::default();
            let mut output = body(ACCESS, REFRESH);
            output["did"] = json!(did);
            output["handle"] = json!(handle);
            http.reply(200, output);
            let error = login_with(
                &MockResolver::default(),
                &http,
                &requested_handle(HANDLE).unwrap(),
                password(),
                &path,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("KIP_ACCOUNT_MISMATCH"));
            assert_sanitized(&error);
            if existing {
                assert_eq!(std::fs::read(path).unwrap(), previous);
            } else {
                assert!(
                    !path.parent().unwrap().exists(),
                    "no storage before validation"
                );
            }
        }
    }
}

#[tokio::test]
async fn identity_and_pds_validation_precede_sending_password_or_writing() {
    for update in [
        json!({"id": "did:plc:someoneelse"}),
        json!({"alsoKnownAs": ["at://other.org"]}),
        json!({"service": []}),
        json!({"service": [{"type":"AtprotoPersonalDataServer","id":"#pds","serviceEndpoint":"http://account-pds.test"}]}),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config/whoami.json");
        let mut resolver = MockResolver::default();
        for (key, value) in update.as_object().unwrap() {
            resolver.doc[key] = value.clone();
        }
        let http = MockHttp::default();
        let error = login_with(
            &resolver,
            &http,
            &requested_handle(HANDLE).unwrap(),
            password(),
            &path,
        )
        .await
        .unwrap_err();
        assert_sanitized(&error);
        assert!(!path.parent().unwrap().exists());
        http.assert_calls(&[]);
    }
    for endpoint in [
        "http://account-pds.test",
        "https://user:fixture-private-detail@account-pds.test",
        "https://account-pds.test/?fixture-private-detail",
        "https://account-pds.test/#fixture-private-detail",
    ] {
        assert_sanitized(&validate_pds(&Url::parse(endpoint).unwrap()).unwrap_err());
    }
}

#[tokio::test]
async fn create_auth_transport_parse_and_invalid_token_errors_are_private() {
    for case in 0..8 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config/whoami.json");
        let http = MockHttp::default();
        match case {
            0 => http.transport_failure(),
            1 => http.reply(
                400,
                json!({"error":"AuthFactorTokenRequired", "message":PASSWORD}),
            ),
            2 => http.reply(
                401,
                json!({"error":"AuthenticationRequired", "message":PRIVATE}),
            ),
            3 => http.reply(429, json!({"error":"RateLimitExceeded", "message":REFRESH})),
            4 => http.raw(200, PRIVATE.as_bytes().to_vec()),
            5 => http.reply(500, json!({"error":"ServerError", "message":ACCESS})),
            6 => {
                let mut output = body(PASSWORD, REFRESH);
                output["private"] = json!(PRIVATE);
                http.reply(200, output);
            }
            7 => {
                let mut output = body(ACCESS, REFRESH);
                output["active"] = json!(false);
                http.reply(200, output);
            }
            _ => unreachable!(),
        }
        let error = login_with(
            &MockResolver::default(),
            &http,
            &requested_handle(HANDLE).unwrap(),
            password(),
            &path,
        )
        .await
        .unwrap_err();
        assert_sanitized(&error);
        assert!(!path.parent().unwrap().exists());
    }
}

#[tokio::test]
async fn even_jwt_shaped_password_echoes_cannot_be_persisted() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config/whoami.json");
    let http = MockHttp::default();
    // The protocol leaves password syntax opaque. A malicious/buggy server must
    // not be able to persist it by echoing it in an otherwise JWT-shaped field.
    let sentinel = "fixture.secret.password";
    for (access, refresh) in [(sentinel, REFRESH), (ACCESS, sentinel)] {
        http.reply(200, body(access, refresh));
        let secret = password_from_env_with("BLUESKY_PASSWD", |_| Ok(sentinel.into())).unwrap();
        let error = login_with(
            &MockResolver::default(),
            &http,
            &requested_handle(HANDLE).unwrap(),
            secret,
            &path,
        )
        .await
        .unwrap_err();
        assert_sanitized(&error);
        assert!(!format!("{error:?}").contains(sentinel));
        assert!(!path.parent().unwrap().exists());
    }
}

#[tokio::test]
async fn persistence_failure_is_sanitized_and_leaves_no_secret_or_temp_file() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fixture-private-detail");
    std::fs::create_dir(&path).unwrap(); // not a regular session file
    let http = MockHttp::default();
    http.reply(200, body(ACCESS, REFRESH));
    let error = login_with(
        &MockResolver::default(),
        &http,
        &requested_handle(HANDLE).unwrap(),
        password(),
        &path,
    )
    .await
    .unwrap_err();
    assert_sanitized(&error);
    assert!(std::fs::read_dir(&path).unwrap().next().is_none());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
}

#[tokio::test]
async fn expired_access_refreshes_once_rotates_privately_and_restores_without_password() {
    for status in [400, 401] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config/whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let client = pds(&info, &path, http.clone());
        http.reply(status, json!({"error":"ExpiredToken", "message":PRIVATE}));
        http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
        http.reply(200, json!({"records":[]}));
        assert!(
            client
                .list_records(BOOKMARK_COLLECTION, None, true)
                .await
                .unwrap()
                .is_empty()
        );
        assert_minimal_store(&path);
        // refreshSession has no input schema. Real PDS servers reject even
        // JSON null, which the SDK serializes from its unit request type.
        {
            let requests = http.requests.lock().unwrap();
            let refresh = requests
                .iter()
                .find(|request| {
                    request
                        .uri()
                        .path()
                        .ends_with("/com.atproto.server.refreshSession")
                })
                .unwrap();
            assert!(
                refresh.body().is_empty(),
                "refreshSession must send no body"
            );
            assert!(refresh.headers().get("content-type").is_none());
        }
        let saved = SavedAppSession::read(&path).unwrap();
        assert!(
            saved.access_jwt == ACCESS_NEXT && saved.refresh_jwt == REFRESH_NEXT,
            "must persist token rotation"
        );
        drop(client);
        // Independent later invocation rehydrates from only session material.
        let later = MockHttp::default();
        let client = pds(&info, &path, later.clone());
        later.reply(200, json!({"records":[]}));
        client
            .list_records(BOOKMARK_COLLECTION, None, true)
            .await
            .unwrap();
        http.assert_calls(&[
            ("POST", "com.atproto.server.createSession", None),
            ("GET", "com.atproto.repo.listRecords", Some(ACCESS)),
            ("POST", "com.atproto.server.refreshSession", Some(REFRESH)),
            ("GET", "com.atproto.repo.listRecords", Some(ACCESS_NEXT)),
        ]);
        later.assert_calls(&[("GET", "com.atproto.repo.listRecords", Some(ACCESS_NEXT))]);
    }
}

#[tokio::test]
async fn add_transport_uses_rotated_session_and_retries_same_record_once() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let client = pds(&info, &path, http.clone());
    http.reply(400, json!({"error":"ExpiredToken"}));
    http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
    let uri = format!("at://{DID}/{BOOKMARK_COLLECTION}/fixturekey");
    http.reply(
        200,
        json!({"uri":uri, "cid":"bafyreiclbzdovdyoyzymb7t3getdeam3hgwqxszgth5ukj6o3tkoftthei"}),
    );
    let record = json!({"$type": BOOKMARK_COLLECTION, "subject": "https://article.test/", "createdAt":"2026-01-01T00:00:00Z"});
    let output = client
        .create_record(BOOKMARK_COLLECTION, Some("fixturekey"), &record)
        .await
        .unwrap();
    assert_eq!(output.uri, uri);
    let requests = http.requests.lock().unwrap();
    assert!(
        requests[1].body() == requests[3].body(),
        "retry must preserve record bytes"
    );
    drop(requests);
    http.assert_calls(&[
        ("POST", "com.atproto.server.createSession", None),
        ("POST", "com.atproto.repo.createRecord", Some(ACCESS)),
        ("POST", "com.atproto.server.refreshSession", Some(REFRESH)),
        ("POST", "com.atproto.repo.createRecord", Some(ACCESS_NEXT)),
    ]);
}

#[tokio::test]
async fn refresh_mismatches_invalid_material_and_failures_never_overwrite_or_retry() {
    for case in 0..10 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let before = std::fs::read(&path).unwrap();
        let client = pds(&info, &path, http.clone());
        http.reply(401, json!({"error":"ExpiredToken"}));
        match case {
            0 => {
                let mut out = body(ACCESS_NEXT, REFRESH_NEXT);
                out["did"] = json!("did:plc:wrongaccount");
                http.reply(200, out);
            }
            1 => {
                let mut out = body(ACCESS_NEXT, REFRESH_NEXT);
                out["handle"] = json!("other.org");
                http.reply(200, out);
            }
            2 => {
                let mut out = body(ACCESS_NEXT, REFRESH_NEXT);
                out["handle"] = json!("@tijs.org");
                http.reply(200, out);
            }
            3 => http.transport_failure(),
            4 => http.reply(400, json!({"error":"ExpiredToken", "message":PRIVATE})),
            5 => http.reply(503, json!({"error":"ServerError", "message":PASSWORD})),
            6 => http.raw(200, PRIVATE.as_bytes().to_vec()),
            7 => http.reply(200, body(ACCESS_NEXT, PASSWORD)),
            8 => {
                let mut out = body(ACCESS_NEXT, REFRESH_NEXT);
                out["active"] = json!(false);
                http.reply(200, out);
            }
            9 => {
                let mut out = body(ACCESS_NEXT, REFRESH_NEXT);
                out["handle"] = json!("Tijs.org");
                http.reply(200, out);
            }
            _ => unreachable!(),
        }
        let error = client
            .list_records(BOOKMARK_COLLECTION, None, true)
            .await
            .unwrap_err();
        assert_sanitized(&error);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            http.requests.lock().unwrap().len(),
            3,
            "must not retry after failed refresh"
        );
    }
}

#[tokio::test]
async fn refreshed_request_is_retried_at_most_once_and_nonexpiry_never_refreshes() {
    for status in [400, 401] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let client = pds(&info, &path, http.clone());
        http.reply(status, json!({"error":"ExpiredToken"}));
        http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
        http.reply(status, json!({"error":"ExpiredToken", "message":PRIVATE}));
        assert_sanitized(
            &client
                .list_records(BOOKMARK_COLLECTION, None, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(http.requests.lock().unwrap().len(), 4);
    }
    for (status, error_code) in [
        (400, "InvalidToken"),
        (401, "AuthenticationRequired"),
        (429, "RateLimitExceeded"),
        (503, "ServerError"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let before = std::fs::read(&path).unwrap();
        let client = pds(&info, &path, http.clone());
        http.reply(
            status,
            json!({"error":error_code, "message": format!("{PRIVATE} {ACCESS} {REFRESH}")}),
        );
        assert_sanitized(
            &client
                .list_records(BOOKMARK_COLLECTION, None, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(
            http.requests.lock().unwrap().len(),
            2,
            "must not assume arbitrary auth errors mean expiry"
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}

#[tokio::test]
async fn malformed_or_superseded_local_session_fails_closed_without_fallback_login() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let client = pds(&info, &path, http.clone());
    // A later explicit OAuth login must not be replaced by this older process.
    let oauth = br#"{"did":"did:plc:oldfixture","handle":"old.test","session_id":"new-oauth"}"#;
    config::write_private_file(&path, oauth).unwrap();
    http.reply(401, json!({"error":"ExpiredToken"}));
    http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
    assert_sanitized(
        &client
            .list_records(BOOKMARK_COLLECTION, None, true)
            .await
            .unwrap_err(),
    );
    assert_eq!(std::fs::read(&path).unwrap(), oauth);
    assert_sanitized(
        &restore_with(&info, &path, MockHttp::default())
            .err()
            .unwrap(),
    );
    std::fs::write(&path, PRIVATE).unwrap();
    assert_sanitized(
        &restore_with(&info, &path, MockHttp::default())
            .err()
            .unwrap(),
    );
}

#[tokio::test]
async fn every_pds_operation_sanitizes_transport_and_raw_response_errors() {
    for operation in 0..5 {
        for failure in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("whoami.json");
            let http = MockHttp::default();
            let info = login_fixture(&path, &http).await;
            let client = pds(&info, &path, http.clone());
            match failure {
                0 => http.transport_failure(),
                1 => http.reply(500, json!({"error":"ServerError", "message":format!("{PRIVATE} {PASSWORD} {ACCESS} {REFRESH} {DID} {HANDLE}")})),
                2 => http.reply(400, json!({"error":"InvalidSwap", "message":format!("{PRIVATE} {PASSWORD} {ACCESS} {REFRESH} {DID} {HANDLE}")})),
                3 => http.raw(200, PRIVATE.as_bytes().to_vec()),
                _ => unreachable!(),
            }
            let record = json!({"subject":"https://article.test/"});
            let result = match operation {
                0 => client
                    .list_records(BOOKMARK_COLLECTION, None, true)
                    .await
                    .map(|_| ()),
                1 => client
                    .create_record(BOOKMARK_COLLECTION, Some("fixturekey"), &record)
                    .await
                    .map(|_| ()),
                2 => client
                    .get_record(BOOKMARK_COLLECTION, "fixturekey")
                    .await
                    .map(|_| ()),
                3 => {
                    client
                        .put_record(BOOKMARK_COLLECTION, "fixturekey", record)
                        .await
                }
                4 => {
                    client
                        .delete_record(BOOKMARK_COLLECTION, "fixturekey")
                        .await
                }
                _ => unreachable!(),
            };
            assert_sanitized(&result.unwrap_err());
            assert_eq!(
                http.requests.lock().unwrap().len(),
                2,
                "no implicit login/refresh on arbitrary errors"
            );
        }
    }
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);
impl tracing::field::Visit for LogCapture {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .lock()
            .unwrap()
            .extend_from_slice(format!("{field}={value:?}\n").as_bytes());
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attributes.record(&mut self.clone());
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut self.clone());
    }
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

#[tokio::test]
async fn create_refresh_and_transport_failures_never_log_secret_material() {
    let logs = LogCapture::default();
    let _guard = tracing::subscriber::set_default(logs.clone());
    tracing::trace!(capture_ready = true);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let client = pds(&info, &path, http.clone());
    http.reply(401, json!({"error":"ExpiredToken"}));
    http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
    http.transport_failure();
    assert_sanitized(
        &client
            .list_records(BOOKMARK_COLLECTION, None, true)
            .await
            .unwrap_err(),
    );
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("capture_ready"),
        "capture must observe trace-level fields"
    );
    for secret in [
        PASSWORD,
        ACCESS,
        REFRESH,
        ACCESS_NEXT,
        REFRESH_NEXT,
        PRIVATE,
    ] {
        assert!(!text.contains(secret), "secret material in trace logs");
    }
    assert_minimal_store(&path);
}
