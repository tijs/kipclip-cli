//! Regressions for the independent auth review. All secrets are synthetic;
//! subprocesses execute only this test binary against the explicit temp store.
use super::*;
use crate::kipclip::app_session::discovery::DiscoveryResolver;
use crate::kipclip::auth::activate_session_info_at;

fn canonical() -> Value {
    json!({"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint":PDS})
}

#[tokio::test]
async fn same_type_decoy_before_canonical_never_receives_password() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let mut resolver = MockResolver::default();
    resolver.doc["service"] = json!([
        {"id":"#decoy", "type":"AtprotoPersonalDataServer", "serviceEndpoint":"https://decoy.test"},
        canonical(),
    ]);
    let http = MockHttp::default();
    http.reply(200, body(ACCESS, REFRESH));
    login_with(
        &resolver,
        &http,
        &requested_handle(HANDLE).unwrap(),
        password(),
        &path,
    )
    .await
    .unwrap();
    http.assert_calls(&[("POST", "com.atproto.server.createSession", None)]);
    assert_minimal_store(&path);
}

#[tokio::test]
async fn missing_wrong_type_duplicate_or_invalid_canonical_services_send_nothing() {
    for services in [
        json!([]),
        json!([{"id":"#decoy", "type":"AtprotoPersonalDataServer", "serviceEndpoint":PDS}]),
        json!([{"id":"#atproto_pds", "type":"OtherService", "serviceEndpoint":PDS}]),
        json!([canonical(), canonical()]),
        json!([canonical(), {"id":"#atproto_pds", "type":"OtherService", "serviceEndpoint":"https://decoy.test"}]),
        json!([canonical(), {"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint":"https://decoy.test"}]),
        json!([{"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint": {"uri":PDS}}]),
        json!([{"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint":"http://decoy.test"}]),
        json!([{"id":"#atproto_pds", "type":"AtprotoPersonalDataServer", "serviceEndpoint":"https://user:fixture-private-detail@decoy.test"}]),
        json!([{"id":"#atproto_pds", "type":"AtprotoPersonalDataServer"}]),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store/whoami.json");
        let mut resolver = MockResolver::default();
        resolver.doc["service"] = services;
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
        http.assert_calls(&[]);
        assert!(!path.parent().unwrap().exists());
    }
}

#[tokio::test]
async fn original_did_document_id_cannot_be_normalized_into_a_match() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("store/whoami.json");
    let mut resolver = MockResolver::default();
    // Jacquard Did::new accepts this and strips at://. The original is invalid.
    let original = format!("at://{DID}");
    assert_eq!(Did::new(&original).unwrap().as_str(), DID);
    resolver.doc["id"] = json!(original);
    let http = MockHttp::default();
    assert_sanitized(
        &login_with(
            &resolver,
            &http,
            &requested_handle(HANDLE).unwrap(),
            password(),
            &path,
        )
        .await
        .unwrap_err(),
    );
    http.assert_calls(&[]);
    assert!(!path.parent().unwrap().exists());
}

#[tokio::test]
async fn exact_expired_token_with_www_authenticate_refreshes_and_retries_once() {
    for status in [400, 401] {
        for challenge in [
            "Bearer error=\"invalid_token\"",
            "DPoP error=\"use_dpop_nonce\"",
            "Basic realm=\"fixture-private-detail\"",
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("whoami.json");
            let http = MockHttp::default();
            let info = login_fixture(&path, &http).await;
            let client = pds(&info, &path, http.clone());
            http.raw_headers(
                status,
                br#"{"error":"ExpiredToken"}"#.to_vec(),
                &[("www-authenticate", challenge)],
            );
            http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
            // A second expiry, also with the challenge, MUST NOT refresh again.
            http.raw_headers(
                status,
                br#"{"error":"ExpiredToken"}"#.to_vec(),
                &[("www-authenticate", challenge)],
            );
            assert_sanitized(
                &client
                    .list_records(BOOKMARK_COLLECTION, None, true)
                    .await
                    .unwrap_err(),
            );
            http.assert_calls(&[
                ("POST", "com.atproto.server.createSession", None),
                ("GET", "com.atproto.repo.listRecords", Some(ACCESS)),
                ("POST", "com.atproto.server.refreshSession", Some(REFRESH)),
                ("GET", "com.atproto.repo.listRecords", Some(ACCESS_NEXT)),
            ]);
            let saved = SavedAppSession::read(&path).unwrap();
            assert!(saved.refresh_jwt == REFRESH_NEXT);
        }
    }
}

#[tokio::test]
async fn expiry_challenge_does_not_hide_body_from_successful_once_only_refresh() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let client = pds(&info, &path, http.clone());
    http.raw_headers(
        401,
        br#"{"error":"ExpiredToken"}"#.to_vec(),
        &[("www-authenticate", "Bearer error=\"invalid_token\"")],
    );
    http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
    http.reply(200, json!({"records":[]}));
    assert!(
        client
            .list_records(BOOKMARK_COLLECTION, None, true)
            .await
            .unwrap()
            .is_empty()
    );
    http.assert_calls(&[
        ("POST", "com.atproto.server.createSession", None),
        ("GET", "com.atproto.repo.listRecords", Some(ACCESS)),
        ("POST", "com.atproto.server.refreshSession", Some(REFRESH)),
        ("GET", "com.atproto.repo.listRecords", Some(ACCESS_NEXT)),
    ]);
}

#[tokio::test]
async fn unrelated_challenges_malformed_codes_and_nonexpiry_status_never_refresh() {
    for (status, bytes) in [
        (401, br#"{"error":"AuthenticationRequired"}"#.as_slice()),
        (
            401,
            br#"{"error":"InvalidToken","message":"ExpiredToken"}"#.as_slice(),
        ),
        (401, br#"{"error":"expiredtoken"}"#.as_slice()),
        (401, br#"{"error":"ExpiredTokenSuffix"}"#.as_slice()),
        (401, br#"{"message":"ExpiredToken"}"#.as_slice()),
        (401, br#"{"error":["ExpiredToken"]}"#.as_slice()),
        (
            401,
            br#"{"error":"Other","error":"ExpiredToken"}"#.as_slice(),
        ),
        (401, b"not json".as_slice()),
        (401, b"".as_slice()),
        (400, br#"{"error":"Other"}"#.as_slice()),
        (403, br#"{"error":"ExpiredToken"}"#.as_slice()),
        (500, br#"{"error":"ExpiredToken"}"#.as_slice()),
        (200, br#"{"error":"ExpiredToken"}"#.as_slice()),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("whoami.json");
        let http = MockHttp::default();
        let info = login_fixture(&path, &http).await;
        let before = std::fs::read(&path).unwrap();
        let client = pds(&info, &path, http.clone());
        http.raw_headers(
            status,
            bytes.to_vec(),
            &[
                ("www-authenticate", "Bearer error=\"invalid_token\""),
                ("dpop-nonce", PRIVATE),
            ],
        );
        assert_sanitized(
            &client
                .list_records(BOOKMARK_COLLECTION, None, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(http.requests.lock().unwrap().len(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

fn bounded_resolver(http: MockHttp) -> DiscoveryResolver<MockHttp> {
    DiscoveryResolver {
        http,
        dns: None,
        opts: Default::default(),
    }
}

#[tokio::test]
async fn credential_post_redirects_are_failures_without_following_or_saving() {
    for status in [301, 302, 303, 307, 308] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store/whoami.json");
        let http = MockHttp::default();
        http.raw_headers(
            status,
            vec![],
            &[("location", "https://decoy.test/credential")],
        );
        assert_sanitized(
            &login_with(
                &MockResolver::default(),
                &http,
                &requested_handle(HANDLE).unwrap(),
                password(),
                &path,
            )
            .await
            .unwrap_err(),
        );
        assert!(!path.parent().unwrap().exists());
        http.assert_calls(&[("POST", "com.atproto.server.createSession", None)]);
        let info = login_fixture(&path, &http).await;
        let before = std::fs::read(&path).unwrap();
        let client = pds(&info, &path, http.clone());
        http.reply(401, json!({"error":"ExpiredToken"}));
        http.raw_headers(
            status,
            vec![],
            &[("location", "https://decoy.test/credential")],
        );
        assert_sanitized(
            &client
                .list_records(BOOKMARK_COLLECTION, None, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        http.assert_calls(&[
            ("POST", "com.atproto.server.createSession", None),
            ("POST", "com.atproto.server.createSession", None),
            ("GET", "com.atproto.repo.listRecords", Some(ACCESS)),
            ("POST", "com.atproto.server.refreshSession", Some(REFRESH)),
        ]);
    }
}

#[tokio::test]
async fn public_handle_fallback_keeps_raw_did_exactness_and_did_web_routing() {
    for raw in [
        "did:web:fixture.test:user:alice",
        "at://did:web:fixture.test:user:alice",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store/whoami.json");
        let discovery = MockHttp::default();
        discovery.reply(404, json!({}));
        discovery.reply(200, json!({"did":raw}));
        let http = MockHttp::default();
        let canonical = !raw.starts_with("at://");
        if canonical {
            let mut doc = MockResolver::default().doc;
            doc["id"] = json!(raw);
            discovery.reply(200, doc);
            let mut output = body(ACCESS, REFRESH);
            output["did"] = json!(raw);
            http.reply(200, output);
        }
        let result = login_with(
            &bounded_resolver(discovery.clone()),
            &http,
            &requested_handle(HANDLE).unwrap(),
            password(),
            &path,
        )
        .await;
        if canonical {
            assert_eq!(result.unwrap().did, raw);
            let requests = discovery.requests.lock().unwrap();
            assert_eq!(
                requests[1].uri(),
                "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=tijs.org"
            );
            assert_eq!(
                requests[2].uri(),
                "https://fixture.test/user/alice/did.json"
            );
        } else {
            assert_sanitized(&result.unwrap_err());
            http.assert_calls(&[]);
            assert!(!path.parent().unwrap().exists());
        }
        assert_credential_free(&discovery);
    }
}

fn assert_credential_free(http: &MockHttp) {
    assert!(http.replies.lock().unwrap().is_empty());
    for request in http.requests.lock().unwrap().iter() {
        assert_eq!(request.method(), "GET");
        assert!(request.body().is_empty());
        assert!(request.headers().get("authorization").is_none());
        assert!(!request.uri().to_string().contains(PASSWORD));
    }
}

#[tokio::test]
async fn discovery_non200_success_and_redirect_statuses_fail_safely_before_credentials() {
    for status in [201, 202, 204, 300, 301, 302, 303, 304, 307, 308] {
        for did_stage in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("store/whoami.json");
            let discovery = MockHttp::default();
            if did_stage {
                discovery.raw(200, DID.as_bytes().to_vec());
            }
            if did_stage {
                discovery.reply(status, MockResolver::default().doc);
            } else {
                discovery.raw(status, DID.as_bytes().to_vec());
            }
            if !did_stage {
                discovery.reply(503, json!({"private":PRIVATE}));
            }
            let http = MockHttp::default();
            let error = login_with(
                &bounded_resolver(discovery.clone()),
                &http,
                &requested_handle(HANDLE).unwrap(),
                password(),
                &path,
            )
            .await
            .unwrap_err();
            assert_sanitized(&error);
            http.assert_calls(&[]);
            assert_credential_free(&discovery);
            assert!(!path.parent().unwrap().exists());
        }
    }
}

#[tokio::test]
async fn discovery_follows_only_bounded_credential_free_https_redirects() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let discovery = MockHttp::default();
    discovery.raw_headers(302, vec![], &[("location", "https://identity.test/handle")]);
    discovery.raw(200, DID.as_bytes().to_vec());
    discovery.raw_headers(307, vec![], &[("location", "/final-document")]);
    discovery.reply(200, MockResolver::default().doc);
    let http = MockHttp::default();
    http.reply(200, body(ACCESS, REFRESH));
    login_with(
        &bounded_resolver(discovery.clone()),
        &http,
        &requested_handle(HANDLE).unwrap(),
        password(),
        &path,
    )
    .await
    .unwrap();
    assert_credential_free(&discovery);
    let requests = discovery.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[2].uri().to_string(),
        format!("https://plc.directory/{DID}")
    );
    assert_eq!(requests[3].uri(), "https://plc.directory/final-document");
    drop(requests);
    http.assert_calls(&[("POST", "com.atproto.server.createSession", None)]);
}

#[tokio::test]
async fn discovery_redirect_loops_downgrades_and_credential_urls_emit_no_password() {
    for destination in [
        "http://decoy.test",
        "https://user:fixture-private-detail@decoy.test",
        "https://decoy.test/#fragment",
        "/loop",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store/whoami.json");
        let discovery = MockHttp::default();
        let count = if destination == "/loop" { 4 } else { 1 };
        for _ in 0..count {
            discovery.raw_headers(302, vec![], &[("location", destination)]);
        }
        discovery.reply(503, json!({})); // Public fallback also fails, offline.
        let http = MockHttp::default();
        assert_sanitized(
            &login_with(
                &bounded_resolver(discovery.clone()),
                &http,
                &requested_handle(HANDLE).unwrap(),
                password(),
                &path,
            )
            .await
            .unwrap_err(),
        );
        assert_credential_free(&discovery);
        assert_eq!(discovery.requests.lock().unwrap().len(), count + 1);
        http.assert_calls(&[]);
        assert!(!path.parent().unwrap().exists());
    }
}

#[tokio::test]
async fn oversized_auth_and_discovery_bodies_are_refused_before_any_save() {
    for stage in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store/whoami.json");
        let http = MockHttp::default();
        let discovery = MockHttp::default();
        let mut padded = body(ACCESS, REFRESH);
        padded["padding"] = json!("x".repeat(MAX_AUTH_BODY));
        match stage {
            0 => {
                http.reply(200, padded);
                assert_sanitized(
                    &login_with(
                        &MockResolver::default(),
                        &http,
                        &requested_handle(HANDLE).unwrap(),
                        password(),
                        &path,
                    )
                    .await
                    .unwrap_err(),
                );
                assert!(!path.exists());
            }
            1 => {
                let info = login_fixture(&path, &http).await;
                let before = std::fs::read(&path).unwrap();
                let client = pds(&info, &path, http.clone());
                http.reply(401, json!({"error":"ExpiredToken"}));
                http.reply(200, padded);
                assert_sanitized(
                    &client
                        .list_records(BOOKMARK_COLLECTION, None, true)
                        .await
                        .unwrap_err(),
                );
                assert_eq!(std::fs::read(&path).unwrap(), before);
                assert_eq!(http.requests.lock().unwrap().len(), 3);
            }
            2 | 3 => {
                if stage == 2 {
                    discovery.raw(200, vec![b'x'; MAX_AUTH_BODY + 1]);
                    discovery.reply(503, json!({}));
                } else {
                    discovery.raw(200, DID.as_bytes().to_vec());
                    let mut doc = MockResolver::default().doc;
                    doc["padding"] = json!("x".repeat(MAX_AUTH_BODY));
                    discovery.reply(200, doc);
                }
                assert_sanitized(
                    &login_with(
                        &bounded_resolver(discovery.clone()),
                        &http,
                        &requested_handle(HANDLE).unwrap(),
                        password(),
                        &path,
                    )
                    .await
                    .unwrap_err(),
                );
                assert_credential_free(&discovery);
                http.assert_calls(&[]);
                assert!(!path.parent().unwrap().exists());
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn legacy_app_session_without_generation_still_restores_and_refreshes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("whoami.json");
    let http = MockHttp::default();
    let info = login_fixture(&path, &http).await;
    let mut legacy: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("generation");
    config::write_private_file(&path, &serde_json::to_vec(&legacy).unwrap()).unwrap();
    let session = restore_with(&info, &path, http.clone()).unwrap();
    http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
    assert!(session.refresh().await.is_ok());
    assert!(SavedAppSession::read(&path).unwrap().refresh_jwt == REFRESH_NEXT);
}

#[cfg(unix)]
mod concurrent {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::process::{Child, Command, Stdio};

    const CHILD_TEST: &str =
        "kipclip::app_session::tests::review::concurrent::session_writer_child";

    fn spawn_writer(path: &Path, action: &str, blocked: bool) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env_clear()
            .env("TMPDIR", std::env::temp_dir())
            .env("HOME", path.parent().unwrap())
            .env("KIP_TEST_STORE", path)
            .env("KIP_TEST_ACTION", action)
            .env("KIP_TEST_BLOCKED", if blocked { "yes" } else { "no" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn wait_for_marker(child: &mut Child, marker: &str) {
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "child ended before handshake"
            );
            if line.trim() == marker {
                break;
            }
        }
        // No further parent reads are needed. Keep stdout alive for libtest.
        child.stdout = Some(reader.into_inner());
    }

    fn finish(child: Child) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "isolated concurrency helper failed"
        );
    }

    fn oauth_info() -> SessionInfo {
        SessionInfo {
            did: DID.into(),
            handle: HANDLE.into(),
            session_id: "new-oauth-fixture".into(),
            auth_method: AuthMethod::OAuth,
        }
    }

    #[tokio::test]
    async fn session_writer_child() {
        let Ok(action) = std::env::var("KIP_TEST_ACTION") else {
            return;
        };
        let path = PathBuf::from(std::env::var_os("KIP_TEST_STORE").unwrap());
        assert!(
            path.starts_with(std::env::temp_dir()),
            "disposable test store only"
        );
        if action == "stale-refresh" {
            let info = SavedAppSession::read(&path).unwrap().info;
            let http = MockHttp::default();
            let session = restore_with(&info, &path, http.clone()).unwrap();
            println!("RESTORED");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONTINUE");
            http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
            assert!(
                session.refresh().await.is_err(),
                "stale process must not commit or retry"
            );
            assert_eq!(http.requests.lock().unwrap().len(), 1);
            return;
        }
        if std::env::var("KIP_TEST_BLOCKED").unwrap() == "yes" {
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path.parent().unwrap().join(".session.lock"))
                .unwrap();
            // Deterministic proof that the *other process* holds the OS lock,
            // after the refresh disk read and before its rename. No sleeps.
            assert_eq!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            println!("LOCK_BLOCKED");
            std::io::stdout().flush().unwrap();
        }
        match action.as_str() {
            "app-login" => {
                login_fixture(&path, &MockHttp::default()).await;
            }
            "oauth-login" => activate_session_info_at(&oauth_info(), &path).unwrap(),
            "logout" => config::clear_sessions(path.parent().unwrap()).unwrap(),
            _ => panic!("invalid isolated test action"),
        }
    }

    #[tokio::test]
    async fn login_and_logout_processes_cannot_enter_refresh_read_rename_transaction() {
        for action in ["app-login", "oauth-login", "logout"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("whoami.json");
            let http = MockHttp::default();
            let info = login_fixture(&path, &http).await;
            let initial_generation = SavedAppSession::read(&path).unwrap().generation;
            let lock_inode = path
                .parent()
                .unwrap()
                .join(".session.lock")
                .metadata()
                .unwrap()
                .ino();
            let children = Arc::new(Mutex::new(Vec::new()));
            let output = children.clone();
            let target = path.clone();
            let mut session = restore_with(&info, &path, http.clone()).unwrap();
            session.store.before_replace = Some(Box::new(move || {
                let mut child = spawn_writer(&target, action, true);
                wait_for_marker(&mut child, "LOCK_BLOCKED");
                output.lock().unwrap().push(child);
            }));
            http.reply(200, body(ACCESS_NEXT, REFRESH_NEXT));
            assert!(session.refresh().await.is_ok());
            for child in children.lock().unwrap().drain(..) {
                finish(child);
            }
            match action {
                "logout" => assert!(!path.exists()),
                "oauth-login" => {
                    let actual: SessionInfo =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    assert_eq!(actual, oauth_info());
                }
                "app-login" => {
                    let actual = SavedAppSession::read(&path).unwrap();
                    assert!(actual.refresh_jwt == REFRESH);
                    assert_ne!(actual.generation, initial_generation);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                path.parent()
                    .unwrap()
                    .join(".session.lock")
                    .metadata()
                    .unwrap()
                    .ino(),
                lock_inode
            );
        }
    }

    #[tokio::test]
    async fn stale_refresh_process_cannot_recreate_logout_or_overwrite_new_login() {
        for action in ["app-login", "oauth-login", "logout"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("whoami.json");
            login_fixture(&path, &MockHttp::default()).await;
            let mut stale = spawn_writer(&path, "stale-refresh", false);
            wait_for_marker(&mut stale, "RESTORED");
            match action {
                // Intentionally identical returned tokens: login generation is
                // what makes this a new session, not token inequality alone.
                "app-login" => {
                    login_fixture(&path, &MockHttp::default()).await;
                }
                "oauth-login" => activate_session_info_at(&oauth_info(), &path).unwrap(),
                "logout" => config::clear_sessions(path.parent().unwrap()).unwrap(),
                _ => unreachable!(),
            }
            let before = std::fs::read(&path).ok();
            writeln!(stale.stdin.as_mut().unwrap(), "CONTINUE").unwrap();
            finish(stale);
            assert_eq!(std::fs::read(&path).ok(), before);
        }
    }
}
