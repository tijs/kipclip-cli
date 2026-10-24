//! No public DNS queries, public connections, or usable credentials. Public
//! resolutions go through the REAL preflight and an in-memory executor. A
//! separate loopback wire test exercises the REAL reqwest builder/pins with a
//! deliberately changed resolver and hostile proxy environment in a child.

use super::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const PASSWORD: &str = "fixture-only-app-password";
const REFRESH: &str = "fixture.refresh.token";
const HOST: &str = "pds-routing.invalid";
const METHODS: [&str; 2] = ["createSession", "refreshSession"];

#[tokio::test]
async fn connection_pool_reuses_only_identical_validated_origin_and_addresses() {
    fn pinned(host: &str, addresses: &[&str]) -> PinnedRequest {
        PinnedRequest {
            url: Url::parse(&format!("https://{host}/xrpc/com.atproto.repo.listRecords")).unwrap(),
            addrs: addresses.iter().map(|s| s.parse().unwrap()).collect(),
            request: http::Request::get("https://fixture.test/")
                .body(Vec::new())
                .unwrap(),
        }
    }
    // No request is dispatched: these clients contain no credentials.
    let first = pinned("pool.fixture.test", &["1.1.1.1:443", "8.8.8.8:443"])
        .pooled_client()
        .unwrap();
    let same = pinned("pool.fixture.test", &["8.8.8.8:443", "1.1.1.1:443"])
        .pooled_client()
        .unwrap();
    assert!(Arc::ptr_eq(&first, &same));
    let changed = pinned("pool.fixture.test", &["8.8.8.8:443"])
        .pooled_client()
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &changed));
    let other_origin = pinned("other.fixture.test", &["1.1.1.1:443", "8.8.8.8:443"])
        .pooled_client()
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &other_origin));
}

fn credential_request(origin: &str, method: &str) -> http::Request<Vec<u8>> {
    let mut request = http::Request::post(format!("{origin}/xrpc/com.atproto.server.{method}"))
        .header("content-type", "application/json");
    let body = if method == "createSession" {
        serde_json::to_vec(&serde_json::json!({"identifier":"fixture.test", "password":PASSWORD}))
            .unwrap()
    } else {
        request = request.header("authorization", format!("Bearer {REFRESH}"));
        b"{}".to_vec()
    };
    request.body(body).unwrap()
}

fn forbidden_addresses() -> Vec<IpAddr> {
    [
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:8.8.8.8",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        "100::1",
        "2001::1",
        "2001:2::1",
        "2001:10::1",
        "2001:20::1",
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "4000::1",
        "5f00::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ]
    .into_iter()
    .map(|ip| ip.parse().unwrap())
    .collect()
}

fn origin(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("https://{ip}"),
        IpAddr::V6(ip) => format!("https://[{ip}]"),
    }
}

#[tokio::test]
async fn blocked_literals_never_resolve_or_dispatch_password_or_refresh_requests() {
    let mut targets: Vec<_> = forbidden_addresses().into_iter().map(origin).collect();
    // url normalizes legacy IPv4 spellings; validation MUST see the actual IP.
    targets.extend(["https://2130706433", "https://0x7f000001", "https://127.1"].map(String::from));
    for target in targets {
        assert!(super::super::validate_pds(&Url::parse(&target).unwrap()).is_err());
        for method in METHODS {
            let error = send_checked_with(
                credential_request(&target, method),
                |_, _| async { panic!("literal IP must not invoke DNS") },
                |_| async { panic!("blocked credential target must never receive a request") },
            )
            .await
            .unwrap_err();
            for diagnostic in [error.to_string(), format!("{error:?}")] {
                assert!(!diagnostic.contains(PASSWORD) && !diagnostic.contains(REFRESH));
                assert!(!diagnostic.contains(&target));
            }
        }
    }
}

#[tokio::test]
async fn production_session_http_refuses_loopback_before_connecting() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("https://{}", listener.local_addr().unwrap());
    for method in METHODS {
        assert!(
            SessionHttp
                .send_http(credential_request(&target, method))
                .await
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn blocked_and_mixed_dns_answers_never_dispatch_either_credential_request() {
    let calls = AtomicUsize::new(0);
    for blocked in forbidden_addresses() {
        for mixed in [false, true] {
            for method in METHODS {
                let mut answers = vec![SocketAddr::new(blocked, 443)];
                if mixed {
                    answers.insert(0, "1.1.1.1:443".parse().unwrap());
                }
                let result = send_checked_with(
                    credential_request(&format!("https://{HOST}"), method),
                    |host, port| {
                        assert_eq!(host, HOST);
                        assert_eq!(port, 443);
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(answers))
                    },
                    |_| async {
                        panic!("a single forbidden DNS result must reject the WHOLE destination")
                    },
                )
                .await;
                assert!(result.is_err());
            }
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        forbidden_addresses().len() * 4
    );
}

#[tokio::test]
async fn failed_or_empty_dns_never_dispatches_credentials() {
    for fail in [false, true] {
        for method in METHODS {
            assert!(
                send_checked_with(
                    credential_request(&format!("https://{HOST}"), method),
                    |_, _| async move {
                        if fail {
                            Err(std::io::Error::other("fixture-private-dns-error"))
                        } else {
                            Ok(Vec::new())
                        }
                    },
                    |_| async { panic!("unresolved credential target must not dispatch") },
                )
                .await
                .is_err()
            );
        }
    }
}

#[tokio::test]
async fn approved_public_dns_answers_are_all_pinned_and_used_by_the_auth_executor() {
    let answers: Vec<SocketAddr> = [
        "1.1.1.1:8443",
        "8.8.8.8:8443",
        "[2606:4700::1111]:8443",
        "[2001:4860:4860::8888]:8443",
    ]
    .map(|addr| addr.parse().unwrap())
    .into();
    let calls = AtomicUsize::new(0);
    for method in METHODS {
        let expected = answers.clone();
        let response = send_checked_with(
            credential_request(&format!("https://{HOST}:8443"), method),
            |host, port| {
                assert_eq!(host, HOST);
                assert_eq!(port, 8443);
                std::future::ready(Ok(answers.clone()))
            },
            |pinned| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(pinned.url.host_str(), Some(HOST));
                assert_eq!(pinned.addrs, expected);
                assert!(pinned.addrs.iter().all(|addr| !is_forbidden_ip(addr.ip())));
                assert_eq!(pinned.request.method(), http::Method::POST);
                if method == "createSession" {
                    assert!(String::from_utf8_lossy(pinned.request.body()).contains(PASSWORD));
                } else {
                    assert_eq!(
                        pinned.request.headers()["authorization"],
                        format!("Bearer {REFRESH}")
                    );
                }
                // The same builder/pin application is exercised over a real
                // loopback socket below; this public case NEVER sends to it.
                let _client = pinned.client_builder().build().unwrap();
                std::future::ready(Ok(http::Response::new(b"fixture-public-response".to_vec())))
            },
        )
        .await
        .unwrap();
        assert_eq!(response.body(), b"fixture-public-response");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn approved_ip_literals_skip_dns_but_still_pass_the_public_policy() {
    for target in ["https://8.8.8.8", "https://[2606:4700::1111]"] {
        for method in METHODS {
            send_checked_with(
                credential_request(target, method),
                |_, _| async { panic!("public literal cannot be redirected by DNS") },
                |pinned| async move {
                    assert_eq!(pinned.addrs.len(), 1);
                    assert!(!is_forbidden_ip(pinned.addrs[0].ip()));
                    Ok(http::Response::new(Vec::new()))
                },
            )
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn refresh_rechecks_dns_instead_of_reusing_an_unvalidated_new_answer() {
    let dispatched = AtomicUsize::new(0);
    for (method, answers, succeeds) in [
        ("createSession", vec!["1.1.1.1:443".parse().unwrap()], true),
        (
            "refreshSession",
            vec!["127.0.0.1:443".parse().unwrap()],
            false,
        ),
    ] {
        let result = send_checked_with(
            credential_request(&format!("https://{HOST}"), method),
            |_, _| async { Ok(answers) },
            |_| async {
                dispatched.fetch_add(1, Ordering::SeqCst);
                Ok(http::Response::new(Vec::new()))
            },
        )
        .await;
        assert_eq!(result.is_ok(), succeeds);
    }
    assert_eq!(dispatched.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn insecure_or_credential_embedded_destinations_fail_before_dns_or_send() {
    for target in [
        "http://pds-routing.invalid",
        "https://user:fixture-only-app-password@pds-routing.invalid",
    ] {
        for method in METHODS {
            assert!(
                send_checked_with(
                    credential_request(target, method),
                    |_, _| async { panic!("invalid destination must not resolve") },
                    |_| async { panic!("invalid destination must not send") },
                )
                .await
                .is_err()
            );
        }
    }
}

struct RebindingDns {
    decoy: SocketAddr,
    calls: Arc<AtomicUsize>,
}

impl reqwest::dns::Resolve for RebindingDns {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let decoy = self.decoy;
        Box::pin(async move {
            let addresses: reqwest::dns::Addrs = Box::new(vec![decoy].into_iter());
            Ok(addresses)
        })
    }
}

const WIRE_CHILD: &str = "kipclip::app_session::transport::routing_tests::pinned_transport_child";

#[tokio::test]
async fn pinned_transport_child() {
    let Ok(approved) = std::env::var("KIP_ROUTING_TEST_APPROVED") else {
        return;
    };
    let approved: SocketAddr = approved.parse().unwrap();
    let decoy: SocketAddr = std::env::var("KIP_ROUTING_TEST_DECOY")
        .unwrap()
        .parse()
        .unwrap();
    assert!(approved.ip().is_loopback() && decoy.ip().is_loopback());
    for method in METHODS {
        // Explicit TEST-ONLY loopback fixture: production preflight never
        // permits loopback or plaintext. Do not add an opt-out to production.
        let url = Url::parse(&format!("http://{HOST}/xrpc/com.atproto.server.{method}")).unwrap();
        let pinned = PinnedRequest {
            url,
            addrs: vec![approved],
            request: credential_request(&format!("http://{HOST}"), method),
        };
        let normal = pinned.client_builder().build().unwrap();
        assert!(
            normal.get(pinned.url.clone()).send().await.is_err(),
            "production remains HTTPS-only"
        );
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let client = pinned
            .client_builder()
            .https_only(false) // fixture override, not reachable from CLI
            .dns_resolver(Arc::new(RebindingDns {
                decoy,
                calls: fallback_calls.clone(),
            }))
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let response = pinned.send_using(client).await.unwrap();
        assert_eq!(
            response.status(),
            307,
            "credential POST redirect must not be followed"
        );
        assert_eq!(
            fallback_calls.load(Ordering::SeqCst),
            0,
            "pinned DNS must override the rebound resolver"
        );
    }
}

#[tokio::test]
async fn real_reqwest_pins_override_rebinding_and_proxies_and_never_follow_post_redirects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let approved = listener.local_addr().unwrap();
    let decoy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let proxy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    decoy.set_nonblocking(true).unwrap();
    proxy.set_nonblocking(true).unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in METHODS {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            loop {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0, "request must be complete");
                buffer.extend_from_slice(&bytes[..count]);
                assert!(buffer.len() < 8192);
                if let Some(end) = buffer.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if buffer.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(buffer).unwrap());
            let reply = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{decoy_addr}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
        requests
    });
    let root = tempfile::tempdir().unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WIRE_CHILD, "--nocapture"])
        .env_clear()
        .env("TMPDIR", std::env::temp_dir())
        .env("HOME", root.path())
        .env("KIP_ROUTING_TEST_APPROVED", approved.to_string())
        .env("KIP_ROUTING_TEST_DECOY", decoy_addr.to_string())
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .kill_on_drop(true);
    for key in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(key, &proxy_url);
    }
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated pin/proxy helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.len(), 2);
    for (request, method) in requests.iter().zip(METHODS) {
        assert!(request.starts_with(&format!(
            "POST /xrpc/com.atproto.server.{method} HTTP/1.1\r\n"
        )));
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: {HOST}\r\n")),
            "original hostname is retained"
        );
    }
    assert!(requests[0].contains(PASSWORD));
    assert!(requests[1].contains(REFRESH));
    assert_eq!(
        decoy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "neither rebound DNS nor POST redirect may reach decoy"
    );
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "environment proxy must receive no request"
    );
}
