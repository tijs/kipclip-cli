//! Offline discovery routing regressions: injected DNS/public pins never use
//! the network. The real reqwest builder is exercised only on loopback in a
//! proxy-poisoned child; plaintext/loopback overrides exist ONLY in that fixture.

use super::*;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const HOST: &str = "discovery-routing.invalid";
const SECRET: &str = "fixture-only-discovery-private-sentinel";
const DID: &str = "did:plc:fixtureaccount";

fn request(target: &str) -> http::Request<Vec<u8>> {
    http::Request::get(target).body(Vec::new()).unwrap()
}

fn addresses(values: &[&str]) -> Vec<SocketAddr> {
    values.iter().map(|value| value.parse().unwrap()).collect()
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
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
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
    .map(|value| value.parse().unwrap())
    .into()
}

fn origin(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("https://{ip}"),
        IpAddr::V6(ip) => format!("https://[{ip}]"),
    }
}

fn reply(status: u16, body: &[u8]) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .body(body.to_vec())
        .unwrap()
}

fn redirect(status: u16, location: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(status)
        .header("location", location)
        .header("set-cookie", format!("private={SECRET}"))
        .header("www-authenticate", format!("Bearer {SECRET}"))
        .body(Vec::new())
        .unwrap()
}

#[tokio::test]
async fn blocked_literals_never_resolve_or_dispatch_discovery() {
    let mut targets: Vec<_> = forbidden_addresses().into_iter().map(origin).collect();
    targets.extend(["https://2130706433", "https://0x7f000001", "https://127.1"].map(String::from));
    for target in targets {
        let error = send_checked_with(
            request(&format!("{target}/.well-known/atproto-did")),
            |_, _| async { panic!("literal must never invoke DNS") },
            |_| async { panic!("forbidden literal must never dispatch") },
        )
        .await
        .unwrap_err();
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(&target) && !diagnostic.contains(SECRET));
        }
    }
}

#[tokio::test]
async fn production_discovery_http_refuses_loopback_without_connecting() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(
        DiscoveryHttp
            .send_http(request(&format!(
                "https://{}/did.json",
                listener.local_addr().unwrap()
            )))
            .await
            .is_err()
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn blocked_or_mixed_dns_answers_in_either_order_never_dispatch() {
    let calls = AtomicUsize::new(0);
    for blocked in forbidden_addresses() {
        for order in 0..3 {
            let mut answers = vec![SocketAddr::new(blocked, 443)];
            if order == 1 {
                answers.insert(0, "1.1.1.1:443".parse().unwrap());
            } else if order == 2 {
                answers.push("[2606:4700::1111]:443".parse().unwrap());
            }
            assert!(
                send_checked_with(
                    request(&format!("https://{HOST}/did.json")),
                    |host, port| {
                        assert_eq!((host.as_str(), port), (HOST, 443));
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(answers))
                    },
                    |_| async { panic!("ANY forbidden answer must refuse the WHOLE hop") },
                )
                .await
                .is_err()
            );
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        forbidden_addresses().len() * 3
    );
}

#[tokio::test]
async fn failed_or_empty_dns_is_sanitized_and_never_dispatches() {
    for fail in [false, true] {
        let error = send_checked_with(
            request(&format!("https://{HOST}/did.json")),
            |_, _| async move {
                if fail {
                    Err(std::io::Error::other(SECRET))
                } else {
                    Ok(Vec::new())
                }
            },
            |_| async { panic!("unresolved destination must not dispatch") },
        )
        .await
        .unwrap_err();
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(SECRET) && !diagnostic.contains(HOST));
        }
    }
}

#[tokio::test]
async fn all_public_answers_reach_the_pin_builder_with_the_original_hostname_and_port() {
    let expected = addresses(&[
        "1.1.1.1:8443",
        "8.8.8.8:8443",
        "[2606:4700::1111]:8443",
        "[2001:4860:4860::8888]:8443",
    ]);
    let target = format!("https://{HOST}:8443/did.json");
    let response = send_checked_with(
        request(&target),
        |host, port| {
            assert_eq!((host.as_str(), port), (HOST, 8443));
            std::future::ready(Ok(expected.clone()))
        },
        |pinned| {
            assert_eq!(pinned.url.as_str(), target);
            assert_eq!(pinned.addrs, expected);
            // The same pin builder is exercised over real loopback sockets
            // below; this public-address test must never connect anywhere.
            let _client = pinned.client_builder().build().unwrap();
            std::future::ready(Ok(reply(200, b"public fixture")))
        },
    )
    .await
    .unwrap();
    assert_eq!(response.body(), b"public fixture");
}

#[tokio::test]
async fn approved_public_literals_do_not_use_dns() {
    for target in [
        "https://8.8.8.8/did.json",
        "https://[2606:4700::1111]/did.json",
    ] {
        send_checked_with(
            request(target),
            |_, _| async { panic!("IP literal must bypass DNS") },
            |pinned| async move {
                assert_eq!(pinned.url.as_str(), target);
                assert_eq!(pinned.addrs.len(), 1);
                assert!(!is_forbidden_ip(pinned.addrs[0].ip()));
                Ok(reply(200, b"literal fixture"))
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn credentials_auth_headers_bodies_and_non_gets_fail_before_dns_or_dispatch() {
    let mut requests = vec![
        request(&format!("http://{HOST}/did.json")),
        request(&format!("https://user:{SECRET}@{HOST}/did.json")),
        http::Request::post(format!("https://{HOST}/did.json"))
            .body(Vec::new())
            .unwrap(),
        http::Request::get(format!("https://{HOST}/did.json"))
            .body(SECRET.as_bytes().to_vec())
            .unwrap(),
    ];
    for header in ["authorization", "proxy-authorization", "cookie"] {
        requests.push(
            http::Request::get(format!("https://{HOST}/did.json"))
                .header(header, SECRET)
                .body(Vec::new())
                .unwrap(),
        );
    }
    for request in requests {
        let error = send_checked_with(
            request,
            |_, _| async { panic!("credential/insecure request must not resolve") },
            |_| async { panic!("credential/insecure request must not dispatch") },
        )
        .await
        .unwrap_err();
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(SECRET) && !diagnostic.contains(HOST));
        }
    }
}

#[derive(Default)]
struct Fixture {
    answers: VecDeque<Vec<SocketAddr>>,
    replies: VecDeque<http::Response<Vec<u8>>>,
    lookups: Vec<(String, u16)>,
    dispatched: Vec<(Url, Vec<SocketAddr>)>,
}

#[derive(Clone, Default)]
struct CheckedHttp(Arc<Mutex<Fixture>>);

impl CheckedHttp {
    fn resolver(
        answers: Vec<Vec<SocketAddr>>,
        replies: Vec<http::Response<Vec<u8>>>,
    ) -> DiscoveryResolver<Self> {
        DiscoveryResolver {
            http: Self(Arc::new(Mutex::new(Fixture {
                answers: answers.into(),
                replies: replies.into(),
                ..Default::default()
            }))),
            dns: None, // Never instantiate or query the real DNS TXT resolver.
            opts: Default::default(),
        }
    }
}

impl HttpClient for CheckedHttp {
    type Error = RequestFailure;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, Self::Error> {
        assert_eq!(request.method(), "GET");
        assert!(request.body().is_empty() && request.headers().is_empty());
        send_checked_with(
            request,
            |host, port| {
                let mut fixture = self.0.lock().unwrap();
                fixture.lookups.push((host, port));
                std::future::ready(Ok(fixture
                    .answers
                    .pop_front()
                    .expect("expected DNS lookup")))
            },
            |pinned| {
                let mut fixture = self.0.lock().unwrap();
                fixture
                    .dispatched
                    .push((pinned.url.clone(), pinned.addrs.clone()));
                let _client = pinned.client_builder().build().unwrap();
                std::future::ready(Ok(fixture.replies.pop_front().expect("expected dispatch")))
            },
        )
        .await
    }
}

#[tokio::test]
async fn well_known_public_resolve_handle_did_web_and_plc_all_use_checked_pins() {
    let expected = addresses(&["1.1.1.1:443", "[2606:4700::1111]:443"]);
    let resolver = CheckedHttp::resolver(
        vec![expected.clone(); 4],
        vec![
            reply(404, b""),
            reply(200, br#"{"did":"did:web:document.invalid:user:alice"}"#),
            reply(200, b"raw did:web document fixture"),
            reply(200, b"raw PLC document fixture"),
        ],
    );
    let did = resolver
        .resolve_handle(&Handle::new("alice.test").unwrap())
        .await
        .unwrap();
    assert_eq!(did.as_str(), "did:web:document.invalid:user:alice");
    assert_eq!(
        resolver
            .resolve_did_doc(&did)
            .await
            .unwrap()
            .buffer
            .as_ref(),
        b"raw did:web document fixture"
    );
    resolver
        .resolve_did_doc(&Did::new(DID).unwrap())
        .await
        .unwrap();
    let fixture = resolver.http.0.lock().unwrap();
    assert!(fixture.answers.is_empty() && fixture.replies.is_empty());
    assert_eq!(
        fixture.lookups,
        [
            ("alice.test".into(), 443),
            ("public.api.bsky.app".into(), 443),
            ("document.invalid".into(), 443),
            ("plc.directory".into(), 443),
        ]
    );
    let targets: Vec<_> = fixture
        .dispatched
        .iter()
        .map(|(url, pins)| {
            assert_eq!(pins, &expected);
            url.as_str()
        })
        .collect();
    assert_eq!(
        targets,
        [
            "https://alice.test/.well-known/atproto-did",
            "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=alice.test",
            "https://document.invalid/user/alice/did.json",
            "https://plc.directory/did:plc:fixtureaccount",
        ]
    );
}

#[tokio::test]
async fn every_resolver_source_refuses_unsafe_dns_without_dispatch() {
    let mixed = addresses(&["1.1.1.1:443", "[::ffff:127.0.0.1]:443"]);
    let resolver = CheckedHttp::resolver(vec![mixed.clone(); 4], vec![]);
    assert!(
        resolver
            .resolve_handle(&Handle::new("alice.test").unwrap())
            .await
            .is_err()
    );
    for did in ["did:web:document.invalid", DID] {
        assert!(
            resolver
                .resolve_did_doc(&Did::new(did).unwrap())
                .await
                .is_err()
        );
    }
    // did:web permits an IP domain syntactically; the network policy must not.
    assert!(
        resolver
            .resolve_did_doc(&Did::new("did:web:127.0.0.1").unwrap())
            .await
            .is_err()
    );
    let fixture = resolver.http.0.lock().unwrap();
    assert_eq!(fixture.lookups.len(), 4);
    assert!(fixture.answers.is_empty() && fixture.dispatched.is_empty());
}

#[tokio::test]
async fn private_redirects_and_same_host_rebinding_stop_before_second_dispatch() {
    let mut destinations: Vec<_> = forbidden_addresses()
        .into_iter()
        .map(|ip| format!("{}/private", origin(ip)))
        .collect();
    destinations.extend(["https://private.invalid/private", "/relative-rebind"].map(String::from));
    for destination in destinations {
        let resolver = CheckedHttp::resolver(
            vec![
                addresses(&["1.1.1.1:443"]),
                addresses(&["8.8.8.8:443", "10.0.0.1:443"]),
            ],
            vec![redirect(302, &destination)],
        );
        assert!(
            resolver
                .get(Url::parse(&format!("https://{HOST}/start")).unwrap())
                .await
                .is_err()
        );
        let fixture = resolver.http.0.lock().unwrap();
        assert_eq!(fixture.dispatched.len(), 1);
        assert_eq!(
            fixture.lookups.len(),
            if destination.contains("invalid") || destination.starts_with('/') {
                2
            } else {
                1
            }
        );
        assert!(fixture.replies.is_empty());
    }
}

#[tokio::test]
async fn redirect_downgrades_credentials_and_fragments_stop_before_dns() {
    for destination in [
        "http://decoy.invalid/private",
        "https://user:fixture-only-discovery-private-sentinel@decoy.invalid/private",
        "https://decoy.invalid/private#fragment",
        "file:///private",
    ] {
        let resolver = CheckedHttp::resolver(
            vec![addresses(&["1.1.1.1:443"])],
            vec![redirect(307, destination)],
        );
        assert!(
            resolver
                .get(Url::parse(&format!("https://{HOST}/start")).unwrap())
                .await
                .is_err()
        );
        let fixture = resolver.http.0.lock().unwrap();
        assert_eq!(fixture.dispatched.len(), 1);
        assert_eq!(fixture.lookups.len(), 1);
    }
}

#[tokio::test]
async fn each_public_redirect_status_re_resolves_and_repins_even_the_same_hostname() {
    for status in [301, 302, 303, 307, 308] {
        let first = addresses(&["1.1.1.1:443", "[2606:4700::1111]:443"]);
        let next = addresses(&["8.8.8.8:443", "[2001:4860:4860::8888]:443"]);
        let resolver = CheckedHttp::resolver(
            vec![first.clone(), next.clone()],
            vec![redirect(status, "/final"), reply(200, b"final")],
        );
        assert_eq!(
            resolver
                .get(Url::parse(&format!("https://{HOST}/start")).unwrap())
                .await
                .unwrap(),
            b"final"
        );
        let fixture = resolver.http.0.lock().unwrap();
        assert_eq!(fixture.lookups, [(HOST.into(), 443), (HOST.into(), 443)]);
        assert_eq!(
            fixture.dispatched,
            [
                (Url::parse(&format!("https://{HOST}/start")).unwrap(), first),
                (Url::parse(&format!("https://{HOST}/final")).unwrap(), next),
            ]
        );
        assert!(fixture.answers.is_empty() && fixture.replies.is_empty());
    }
}

#[tokio::test]
async fn three_redirects_are_allowed_but_a_fourth_is_not_resolved_or_dispatched() {
    for succeeds in [false, true] {
        let mut replies: Vec<_> = (0..MAX_REDIRECTS).map(|_| redirect(302, "/next")).collect();
        replies.push(if succeeds {
            reply(200, b"final")
        } else {
            redirect(302, "https://never.invalid/")
        });
        let resolver = CheckedHttp::resolver(
            vec![addresses(&["1.1.1.1:443"]); MAX_REDIRECTS + 1],
            replies,
        );
        let result = resolver
            .get(Url::parse(&format!("https://{HOST}/start")).unwrap())
            .await;
        assert_eq!(result.is_ok(), succeeds);
        let fixture = resolver.http.0.lock().unwrap();
        assert_eq!(fixture.dispatched.len(), MAX_REDIRECTS + 1);
        assert_eq!(fixture.lookups.len(), MAX_REDIRECTS + 1);
        assert!(fixture.answers.is_empty() && fixture.replies.is_empty());
    }
}

#[tokio::test]
async fn non200_statuses_and_oversized_discovery_bodies_fail_without_panic() {
    for response in [
        reply(201, b""),
        reply(202, b""),
        reply(204, b""),
        reply(300, b""),
        reply(301, b""),
        reply(302, b""),
        reply(303, b""),
        reply(304, b""),
        reply(307, b""),
        reply(308, b""),
        reply(404, SECRET.as_bytes()),
        reply(500, SECRET.as_bytes()),
        reply(200, &vec![b'x'; MAX_AUTH_BODY + 1]),
    ] {
        let resolver = CheckedHttp::resolver(vec![addresses(&["1.1.1.1:443"])], vec![response]);
        let error = resolver
            .get(Url::parse(&format!("https://{HOST}/start")).unwrap())
            .await
            .unwrap_err();
        assert!(!error.to_string().contains(SECRET) && !format!("{error:?}").contains(SECRET));
        assert_eq!(resolver.http.0.lock().unwrap().dispatched.len(), 1);
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
            let answers: reqwest::dns::Addrs = Box::new(vec![decoy].into_iter());
            Ok(answers)
        })
    }
}

const WIRE_CHILD: &str = "kipclip::app_session::discovery::routing_tests::pinned_discovery_child";

#[tokio::test]
async fn pinned_discovery_child() {
    let Ok(approved) = std::env::var("KIP_DISCOVERY_TEST_APPROVED") else {
        return;
    };
    let decoy: SocketAddr = std::env::var("KIP_DISCOVERY_TEST_DECOY")
        .unwrap()
        .parse()
        .unwrap();
    let unavailable: SocketAddr = std::env::var("KIP_DISCOVERY_TEST_UNAVAILABLE")
        .unwrap()
        .parse()
        .unwrap();
    assert!(decoy.ip().is_loopback() && unavailable.ip().is_loopback());
    for (index, approved) in approved.split(',').enumerate() {
        let approved: SocketAddr = approved.parse().unwrap();
        assert!(approved.ip().is_loopback());
        let request = http::Request::get(format!("https://{HOST}/did.json"))
            .header("x-api-key", SECRET)
            .header("referer", SECRET)
            .header("host", "stolen.invalid")
            .body(Vec::new())
            .unwrap();
        let response = send_checked_with(
            request,
            |host, port| {
                assert_eq!((host.as_str(), port), (HOST, 443));
                std::future::ready(Ok(addresses(&["1.1.1.1:443", "[2606:4700::1111]:443"])))
            },
            |mut pinned| async move {
                assert_eq!(
                    pinned.addrs,
                    addresses(&["1.1.1.1:443", "[2606:4700::1111]:443"])
                );
                assert_eq!(pinned.url.host_str(), Some(HOST));
                // TEST-ONLY executor maps the approved public fixture to a
                // loopback listener; production has no unsafe policy override.
                // Exercise both orders: pinning only the first OR only the
                // last address must fail one case. The unlistened IPv6 port
                // has no server; Happy Eyeballs must try the approved IPv4 too.
                pinned.addrs = if index == 0 {
                    vec![unavailable, approved]
                } else {
                    vec![approved, unavailable]
                };
                pinned.url.set_scheme("http").unwrap();
                let normal = pinned.client_builder().build().unwrap();
                assert!(
                    normal.get(pinned.url.clone()).send().await.is_err(),
                    "production remains HTTPS-only"
                );
                let fallback_calls = Arc::new(AtomicUsize::new(0));
                let client = pinned
                    .client_builder()
                    .https_only(false) // ONLY for this plaintext loopback fixture
                    .dns_resolver(Arc::new(RebindingDns {
                        decoy,
                        calls: fallback_calls.clone(),
                    }))
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap();
                let response = pinned.send_using(client).await.unwrap();
                assert_eq!(
                    fallback_calls.load(Ordering::SeqCst),
                    0,
                    "validated pins must override rebound DNS"
                );
                Ok(response)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            302,
            "reqwest must not automatically follow discovery redirects"
        );
    }
}

#[tokio::test]
async fn real_reqwest_applies_each_pin_disables_proxies_redirects_and_strips_secret_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let unavailable = tokio::net::TcpSocket::new_v6().unwrap();
    unavailable.bind("[::1]:0".parse().unwrap()).unwrap();
    let decoy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let proxy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    decoy.set_nonblocking(true).unwrap();
    proxy.set_nonblocking(true).unwrap();
    let mut approved = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..2 {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        approved.push(listener.local_addr().unwrap().to_string());
        servers.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            loop {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0);
                buffer.extend_from_slice(&bytes[..count]);
                assert!(buffer.len() < 8192);
                if buffer.windows(4).any(|part| part == b"\r\n\r\n") { break; }
            }
            stream.write_all(format!(
                "HTTP/1.1 302 Found\r\nLocation: https://stolen.invalid/redirect\r\nSet-Cookie: private={SECRET}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await.unwrap();
            String::from_utf8(buffer).unwrap()
        }));
    }
    let root = tempfile::tempdir().unwrap();
    let proxy_url = format!("http://user:{SECRET}@{}", proxy.local_addr().unwrap());
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", WIRE_CHILD, "--nocapture"])
        .env_clear()
        .env("HOME", root.path())
        .env("TMPDIR", std::env::temp_dir())
        .env("KIP_DISCOVERY_TEST_APPROVED", approved.join(","))
        .env(
            "KIP_DISCOVERY_TEST_UNAVAILABLE",
            unavailable.local_addr().unwrap().to_string(),
        )
        .env(
            "KIP_DISCOVERY_TEST_DECOY",
            decoy.local_addr().unwrap().to_string(),
        )
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
        "isolated discovery pin/proxy helper failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for server in servers {
        let request = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(request.starts_with("GET /did.json HTTP/1.1\r\n"));
        let lower = request.to_ascii_lowercase();
        assert!(
            lower.contains(&format!("host: {HOST}\r\n")),
            "original Host must remain intact"
        );
        for forbidden in [
            SECRET,
            "authorization",
            "cookie",
            "x-api-key",
            "referer",
            "stolen.invalid",
        ] {
            assert!(
                !lower.contains(forbidden),
                "caller/secret header must never reach discovery: {forbidden}"
            );
        }
        assert!(request.ends_with("\r\n\r\n"), "discovery must have no body");
    }
    assert_eq!(
        decoy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "no DNS rebind or automatic redirect may reach the decoy"
    );
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "environment proxy must receive no discovery request"
    );
}
