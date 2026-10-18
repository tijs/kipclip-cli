//! Hardened, read-only HTTP fetching for URL metadata.
//!
//! Deliberately strict: a single GET per hop, no cookies or auth headers, no
//! proxies, a bounded number of redirects with every hop validated,
//! DNS-resolved targets checked against a local/private/reserved blocklist and
//! pinned to the validated addresses, and a streaming body read capped at
//! [`MAX_BODY_BYTES`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use miette::{IntoDiagnostic, Result, miette};
use reqwest::Url;
use reqwest::header;
use url::Host;

use crate::kipclip::url::validate_http_url;

/// Maximum number of bytes read from a response body.
pub const MAX_BODY_BYTES: usize = 512 * 1024; // 512KB — enough for <head>
/// Timeout for a single request (connect, response, body).
pub const TIMEOUT_SECS: u64 = 10;
/// Overall budget for one fetch, including all redirect hops.
pub const OVERALL_TIMEOUT_SECS: u64 = 20;
/// Maximum number of redirects followed.
pub const MAX_REDIRECTS: usize = 5;

const USER_AGENT: &str = "kipclip-bot/1.0 (Bookmark enrichment; +https://kipclip.com)";
const ACCEPT: &str = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1";

/// A completed HTTP exchange.
#[derive(Debug)]
pub struct FetchedPage {
    /// URL of the final response, after redirects.
    pub final_url: Url,
    /// Status of the final response.
    pub status: reqwest::StatusCode,
    /// Capped body when the final response is HTML; `None` otherwise.
    pub html: Option<String>,
}

/// Fetch `url`, refusing connections to local, private, and reserved addresses.
pub async fn fetch_url(url: &str) -> Result<FetchedPage> {
    fetch_with_guard(url, &|ip| !is_forbidden_ip(ip)).await
}

/// Like [`fetch_url`], but with a caller-supplied policy deciding which IPs may
/// be connected to. Tests use this to reach loopback mock servers.
async fn fetch_with_guard<G: Fn(IpAddr) -> bool>(url: &str, allow: &G) -> Result<FetchedPage> {
    tokio::time::timeout(
        Duration::from_secs(OVERALL_TIMEOUT_SECS),
        fetch_inner(url, allow),
    )
    .await
    .map_err(|_| miette!("Timed out fetching {url}"))?
}

async fn fetch_inner<G: Fn(IpAddr) -> bool>(url: &str, allow: &G) -> Result<FetchedPage> {
    let mut current = validate_http_url(url)?;
    reject_credentials(&current)?;
    let mut redirects_followed = 0usize;

    loop {
        // Validate and pin the destination of this hop before connecting.
        let addrs = resolve_and_validate(&current, allow).await?;
        let client = build_client(&current, &addrs)?;
        let resp = client
            .get(current.clone())
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, ACCEPT)
            .send()
            .await
            .map_err(|e| miette!("Failed to fetch {current}: {e}"))?;

        let status = resp.status();

        let location = if is_followable_redirect(status) {
            resp.headers().get(header::LOCATION).cloned()
        } else {
            None
        };
        if let Some(location) = location {
            if redirects_followed >= MAX_REDIRECTS {
                return Err(miette!(
                    "Too many redirects (max {MAX_REDIRECTS}) while fetching {url}"
                ));
            }
            redirects_followed += 1;
            let location = location
                .to_str()
                .map_err(|_| miette!("Invalid redirect location from {current}"))?;
            let next = current
                .join(location)
                .map_err(|e| miette!("Invalid redirect location from {current}: {e}"))?;
            current = validate_http_url(next.as_str())?;
            reject_credentials(&current)?;
            continue;
        }

        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let html = if status.is_success() && is_html_content_type(content_type) {
            Some(read_body_capped(resp).await?)
        } else {
            None
        };
        return Ok(FetchedPage {
            final_url: current,
            status,
            html,
        });
    }
}

fn is_followable_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn is_html_content_type(content_type: &str) -> bool {
    let mime = content_type.split(';').next().unwrap_or("").trim();
    mime.eq_ignore_ascii_case("text/html") || mime.eq_ignore_ascii_case("application/xhtml+xml")
}

fn reject_credentials(url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(miette!("URLs with embedded credentials are not supported"));
    }
    Ok(())
}

/// Build a client for one hop. Redirects are followed manually so that every
/// hop can be validated; proxies are disabled so the address checks below are
/// authoritative; domain targets are pinned to the addresses we validated.
fn build_client(url: &Url, addrs: &[SocketAddr]) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(Host::Domain(domain)) = url.host() {
        builder = builder.resolve_to_addrs(domain, addrs);
    }
    builder.build().into_diagnostic()
}

/// Read at most [`MAX_BODY_BYTES`] from the response, streaming: the read stops
/// as soon as the cap is reached instead of buffering the whole body first.
async fn read_body_capped(mut resp: reqwest::Response) -> Result<String> {
    let mut body = Vec::with_capacity(64 * 1024);
    while body.len() < MAX_BODY_BYTES {
        let Some(chunk) = resp.chunk().await.into_diagnostic()? else {
            break;
        };
        let remaining = MAX_BODY_BYTES - body.len();
        if chunk.len() >= remaining {
            body.extend_from_slice(&chunk[..remaining]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Resolve `url`'s host and return the socket addresses that may be connected
/// to. Every resolved address must pass `allow`, so a hostname that resolves to
/// any forbidden address is refused as a whole.
pub(super) async fn resolve_and_validate<G: Fn(IpAddr) -> bool>(
    url: &Url,
    allow: &G,
) -> Result<Vec<SocketAddr>> {
    resolve_and_validate_with(url, allow, |domain, port| async move {
        tokio::net::lookup_host((domain, port))
            .await
            .map(|addrs| addrs.collect())
    })
    .await
}

/// Same validation/pinning contract with injectable DNS for offline auth tests.
/// Literal addresses bypass DNS, and a mixed public/private answer fails closed.
pub(super) async fn resolve_and_validate_with<G, L, F>(
    url: &Url,
    allow: &G,
    lookup: L,
) -> Result<Vec<SocketAddr>>
where
    G: Fn(IpAddr) -> bool,
    L: FnOnce(String, u16) -> F,
    F: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    let host = url
        .host()
        .ok_or_else(|| miette!("URL has no host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| miette!("URL has no port: {url}"))?;
    match host {
        Host::Ipv4(ip) => validated_single(IpAddr::V4(ip), port, url, allow),
        Host::Ipv6(ip) => validated_single(IpAddr::V6(ip), port, url, allow),
        Host::Domain(domain) => {
            let addrs = lookup(domain.to_owned(), port)
                .await
                .map_err(|e| miette!("Could not resolve {domain}: {e}"))?;
            if addrs.is_empty() {
                return Err(miette!("Could not resolve {domain}"));
            }
            for addr in &addrs {
                check_allowed(addr.ip(), url, allow)?;
            }
            Ok(addrs)
        }
    }
}

fn validated_single<G: Fn(IpAddr) -> bool>(
    ip: IpAddr,
    port: u16,
    url: &Url,
    allow: &G,
) -> Result<Vec<SocketAddr>> {
    check_allowed(ip, url, allow)?;
    Ok(vec![SocketAddr::new(ip, port)])
}

fn check_allowed<G: Fn(IpAddr) -> bool>(ip: IpAddr, url: &Url, allow: &G) -> Result<()> {
    if !allow(ip) {
        return Err(miette!(
            "Refusing to fetch {url}: {ip} is a local, private, or reserved address"
        ));
    }
    Ok(())
}

/// Whether connecting to `ip` must be refused: local, private, link-local,
/// shared, benchmarking, documentation, multicast, or otherwise reserved.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0 // 0.0.0.0/8 (this network)
        || a == 10 // 10.0.0.0/8 (private)
        || a == 127 // 127.0.0.0/8 (loopback)
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 (CGNAT)
        || (a == 169 && b == 254) // 169.254.0.0/16 (link-local)
        || (a == 172 && (16..=31).contains(&b)) // 172.16.0.0/12 (private)
        || (a == 192 && b == 168) // 192.168.0.0/16 (private)
        || (a == 192 && b == 0 && (c == 0 || c == 2)) // 192.0.0.0/24, 192.0.2.0/24
        || (a == 192 && b == 88 && c == 99) // 192.88.99.0/24 (6to4 relay)
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 (benchmarking)
        || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24 (TEST-NET-2)
        || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24 (TEST-NET-3)
        || a >= 224 // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    let [s0, s1, ..] = ip.segments();
    // Only global unicast 2000::/3 is eligible. This also excludes every
    // mapped/compatible IPv4, NAT64, local, multicast and unallocated range.
    (s0 & 0xe000) != 0x2000
        || (s0 == 0x2001 && s1 < 0x0200) // 2001::/23 protocol/special assignments
        || (s0 == 0x2001 && s1 == 0x0db8) // 2001:db8::/32 (documentation)
        || s0 == 0x2002 // 2002::/16 (6to4)
        || (s0 == 0x3fff && (s1 & 0xf000) == 0) // 3fff::/20 (documentation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use url::Host;

    /// Production blocklist, but with loopback allowed so tests can reach local
    /// mock servers.
    fn test_guard(ip: IpAddr) -> bool {
        !is_forbidden_ip(ip) || ip.is_loopback()
    }

    async fn read_request_head(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 64 * 1024 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Spawn a mock HTTP/1.1 server on loopback. `respond` builds the raw
    /// response for each request. Returns the bound address and a counter of
    /// accepted connections.
    async fn spawn_server<F>(respond: F) -> (SocketAddr, Arc<AtomicUsize>)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let request = read_request_head(&mut stream).await;
                let response = respond(&request);
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (addr, hits)
    }

    /// Spawn a one-shot mock server that streams `total` bytes of HTML, either
    /// with a declared Content-Length or chunked. The returned flag is set only
    /// if the full body was written, i.e. the client kept reading.
    async fn spawn_streaming_server(
        total: usize,
        chunked: bool,
    ) -> (SocketAddr, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let prefix = b"<html><head><title>Small</title>";
        let tail = b"<meta name=\"description\" content=\"LATE\">";
        let mut body = Vec::with_capacity(total);
        body.extend_from_slice(prefix);
        body.resize(total - tail.len(), b'A');
        body.extend_from_slice(tail);
        let body = Arc::new(body);

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wrote_all = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&wrote_all);
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            read_request_head(&mut stream).await;
            let headers = if chunked {
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            };
            let write = async {
                stream.write_all(headers.as_bytes()).await?;
                if chunked {
                    for chunk in body.chunks(64 * 1024) {
                        stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await?;
                        stream.write_all(chunk).await?;
                        stream.write_all(b"\r\n").await?;
                    }
                    stream.write_all(b"0\r\n\r\n").await?;
                } else {
                    stream.write_all(body.as_slice()).await?;
                }
                stream.shutdown().await?;
                Ok::<(), std::io::Error>(())
            };
            let completed = matches!(
                tokio::time::timeout(Duration::from_secs(10), write).await,
                Ok(Ok(()))
            );
            flag.store(completed, Ordering::SeqCst);
        });
        (addr, wrote_all, handle)
    }

    fn html_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn redirect_response(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    #[test]
    fn forbidden_ip_ranges() {
        let forbidden = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
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
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ];
        for ip in forbidden {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(parsed), "{ip} should be blocked");
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "2001:4860:4860::8888",
        ];
        for ip in allowed {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_forbidden_ip(parsed), "{ip} should be allowed");
        }
    }

    #[test]
    fn numeric_ipv4_hosts_are_normalized() {
        let url = Url::parse("http://2130706433/").unwrap();
        assert!(
            matches!(url.host(), Some(Host::Ipv4(_))),
            "expected IPv4 host, got {:?}",
            url.host()
        );
    }

    #[tokio::test]
    async fn fetch_url_refuses_loopback_without_connecting() {
        let (addr, hits) = spawn_server(|_| html_response("<html></html>")).await;
        let err = fetch_url(&format!("http://127.0.0.1:{}/", addr.port()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refusing"), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fetch_url_refuses_local_and_private_targets() {
        for url in [
            "http://localhost/",
            "http://127.0.0.1:9/",
            "http://2130706433/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://[::1]:8080/",
            "http://[fe80::1]/",
        ] {
            let err = fetch_url(url).await.unwrap_err();
            assert!(err.to_string().contains("Refusing"), "{url}: {err}");
        }
    }

    #[tokio::test]
    async fn fetch_url_rejects_embedded_credentials() {
        let err = fetch_url("http://user:pass@127.0.0.1/").await.unwrap_err();
        assert!(err.to_string().contains("credentials"), "{err}");
    }

    #[tokio::test]
    async fn fetches_html_from_allowed_host() {
        let (addr, hits) =
            spawn_server(|_| html_response("<html><head><title>Hello</title></head></html>")).await;
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let page = fetch_with_guard(&url, &test_guard).await.unwrap();
        assert_eq!(page.status.as_u16(), 200);
        assert_eq!(page.final_url, Url::parse(&url).unwrap());
        assert!(
            page.html
                .as_deref()
                .unwrap()
                .contains("<title>Hello</title>")
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sends_no_cookies_or_auth_headers() {
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        let (addr, _hits) = spawn_server(move |request| {
            sink.lock().unwrap().push(request.to_string());
            html_response("<html></html>")
        })
        .await;
        let url = format!("http://127.0.0.1:{}/", addr.port());
        fetch_with_guard(&url, &test_guard).await.unwrap();

        let requests = captured.lock().unwrap();
        let head = requests.last().expect("request captured");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("user-agent: kipclip-bot"), "{head}");
        assert!(!lower.contains("cookie"), "{head}");
        assert!(!lower.contains("authorization"), "{head}");
    }

    #[tokio::test]
    async fn follows_redirect_and_reports_final_url() {
        let (final_addr, final_hits) =
            spawn_server(|_| html_response("<html><head><title>Redirected</title></head></html>"))
                .await;
        let target = format!("http://127.0.0.1:{}/final", final_addr.port());
        let target_for_closure = target.clone();
        let (start_addr, start_hits) =
            spawn_server(move |_| redirect_response(&target_for_closure)).await;
        let start = format!("http://127.0.0.1:{}/start", start_addr.port());

        let page = fetch_with_guard(&start, &test_guard).await.unwrap();
        assert_eq!(page.final_url, Url::parse(&target).unwrap());
        assert!(page.html.as_deref().unwrap().contains("Redirected"));
        assert_eq!(start_hits.load(Ordering::SeqCst), 1);
        assert_eq!(final_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refuses_redirect_to_blocked_destination() {
        for (blocked, needle) in [
            ("http://169.254.169.254/latest/meta-data/", "Refusing"),
            ("http://10.0.0.1/", "Refusing"),
            ("http://192.168.1.1/admin", "Refusing"),
            ("file:///etc/passwd", "HTTP(S)"),
        ] {
            let blocked = blocked.to_string();
            let (addr, hits) = spawn_server(move |_| redirect_response(&blocked)).await;
            let url = format!("http://127.0.0.1:{}/", addr.port());
            let err = fetch_with_guard(&url, &test_guard).await.unwrap_err();
            assert!(err.to_string().contains(needle), "{err}");
            assert_eq!(
                hits.load(Ordering::SeqCst),
                1,
                "only the first hop may be fetched for {needle}"
            );
        }
    }

    #[tokio::test]
    async fn refuses_redirect_loop_after_max_hops() {
        let (addr, hits) = spawn_server(|_| redirect_response("/next")).await;
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let err = fetch_with_guard(&url, &test_guard).await.unwrap_err();
        assert!(err.to_string().contains("redirects"), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), MAX_REDIRECTS + 1);
    }

    async fn assert_body_read_is_capped(chunked: bool) {
        let total = 32 * 1024 * 1024;
        let (addr, wrote_all, handle) = spawn_streaming_server(total, chunked).await;
        let url = format!("http://127.0.0.1:{}/", addr.port());

        let page = fetch_with_guard(&url, &test_guard).await.unwrap();
        let html = page.html.expect("html body");

        // Let the server task observe the client's early close (or finish).
        let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;

        assert!(html.len() <= MAX_BODY_BYTES, "body exceeds the cap");
        assert!(html.contains("<title>Small</title>"));
        assert!(
            !html.contains("LATE"),
            "content beyond the cap must not be read"
        );
        assert!(
            !wrote_all.load(Ordering::SeqCst),
            "client kept reading past the cap (chunked={chunked})"
        );
    }

    #[tokio::test]
    async fn caps_response_body_read_with_content_length() {
        assert_body_read_is_capped(false).await;
    }

    #[tokio::test]
    async fn caps_response_body_read_when_chunked() {
        assert_body_read_is_capped(true).await;
    }

    #[tokio::test]
    async fn extracts_metadata_from_redirected_page() {
        let (final_addr, _) = spawn_server(|_| {
            html_response(
                r#"<html><head><title>Final Page</title><meta property="og:image" content="/img/pic.jpg"></head></html>"#,
            )
        })
        .await;
        let target = format!("http://127.0.0.1:{}/article", final_addr.port());
        let target_for_closure = target.clone();
        let (start_addr, _) = spawn_server(move |_| redirect_response(&target_for_closure)).await;
        let url = format!("http://127.0.0.1:{}/start", start_addr.port());

        let page = fetch_with_guard(&url, &test_guard).await.unwrap();
        let metadata = crate::kipclip::enrich::parse_html_metadata(
            page.html.as_deref().expect("html"),
            &page.final_url,
        );
        let expected_image = format!("http://127.0.0.1:{}/img/pic.jpg", final_addr.port());
        let expected_favicon = format!("http://127.0.0.1:{}/favicon.ico", final_addr.port());
        assert_eq!(metadata.title.as_deref(), Some("Final Page"));
        assert_eq!(metadata.image.as_deref(), Some(expected_image.as_str()));
        assert_eq!(metadata.favicon.as_deref(), Some(expected_favicon.as_str()));
    }
}
