//! App-password transport only. OAuth retains Jacquard's normal transport.
//! Authentication and discovery bodies are capped at 256 KiB while streaming,
//! regardless of Content-Length. Other app-session XRPC bodies allow 8 MiB.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use jacquard::http_client::HttpClient;
use jacquard::xrpc::{
    CallOptions, Response, XrpcRequest, XrpcResponse, build_http_request, process_response,
};
use miette::{Result, miette};
use serde::Deserialize;
use url::Host;
use url::Url;

use super::super::auth::RequestFailure;
use super::super::fetch::{is_forbidden_ip, resolve_and_validate_with};

pub(super) const MAX_AUTH_BODY: usize = 256 * 1024;
const MAX_RECORD_BODY: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct SessionHttp;

fn transport_error() -> miette::Report {
    miette!("KIP_AUTH_TRANSPORT: Could not initialize secure authentication transport.")
}

pub(super) fn private_client() -> Result<reqwest::Client> {
    private_client_builder()
        .build()
        .map_err(|_| transport_error())
}

pub(super) fn private_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        // In particular, credential-bearing POSTs must NEVER follow redirects.
        // Discovery follows validated redirects explicitly, without credentials.
        .redirect(reqwest::redirect::Policy::none())
        // An environment/system proxy can resolve the target itself, bypassing
        // both our IP policy and pinned DNS. Credential transport is direct.
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
}

/// Only constructed after every DNS result (or the literal IP) is approved.
/// Keep the URL's hostname for TLS/SNI/Host; pin its complete approved answer.
struct PinnedRequest {
    url: Url,
    addrs: Vec<SocketAddr>,
    request: http::Request<Vec<u8>>,
}

#[derive(PartialEq, Eq)]
struct ConnectionKey {
    origin: String,
    addrs: Vec<SocketAddr>,
}

type ClientCache = Mutex<Vec<(ConnectionKey, Arc<reqwest::Client>)>>;
static CLIENTS: OnceLock<ClientCache> = OnceLock::new();

impl PinnedRequest {
    fn pooled_client(&self) -> std::result::Result<Arc<reqwest::Client>, RequestFailure> {
        // Preflight still runs for EVERY request before reaching this method.
        // Share TLS connections only for the same origin and exact validated
        // address set. A changed/forbidden DNS answer cannot use an old pool.
        let mut addrs = self.addrs.clone();
        addrs.sort_unstable();
        addrs.dedup();
        let key = ConnectionKey {
            origin: self.url.origin().ascii_serialization(),
            addrs,
        };
        let mut clients = CLIENTS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .map_err(|_| RequestFailure)?;
        if let Some((_, client)) = clients.iter().find(|(stored, _)| stored == &key) {
            return Ok(client.clone());
        }
        let client = Arc::new(self.client_builder().build().map_err(|_| RequestFailure)?);
        if clients.len() >= 8 {
            clients.remove(0);
        }
        clients.push((key, client.clone()));
        Ok(client)
    }

    fn client_builder(&self) -> reqwest::ClientBuilder {
        let builder = private_client_builder();
        match self.url.host() {
            Some(Host::Domain(domain)) => builder.resolve_to_addrs(domain, &self.addrs),
            // reqwest's resolve overrides do not apply to IP literals. Those
            // were validated directly and cannot be rebound through DNS.
            _ => builder,
        }
    }

    async fn send(self) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure> {
        let client = self.pooled_client()?;
        self.send_using((*client).clone()).await
    }

    async fn send_using(
        self,
        client: reqwest::Client,
    ) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure> {
        let nsid = self
            .request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default();
        let limit = xrpc_limit(nsid);
        let (parts, body) = self.request.into_parts();
        let response = client
            .request(parts.method, self.url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| RequestFailure)?;
        read_limited(response, limit).await
    }
}

/// Lookup and executor are injectable so public DNS answers can be tested
/// without connecting to a public address or exposing any real credentials.
async fn send_checked_with<L, F, S, O>(
    request: http::Request<Vec<u8>>,
    lookup: L,
    send: S,
) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure>
where
    L: FnOnce(String, u16) -> F,
    F: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
    S: FnOnce(PinnedRequest) -> O,
    O: std::future::Future<Output = std::result::Result<http::Response<Vec<u8>>, RequestFailure>>,
{
    let url = Url::parse(&request.uri().to_string()).map_err(|_| RequestFailure)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(RequestFailure);
    }
    // DNS is part of the bounded preflight, BEFORE any body/bearer is sent.
    // Re-resolve/revalidate for each request, including refresh after restore;
    // never let an unvalidated fallback resolver or pooled connection choose it.
    let addrs = tokio::time::timeout(
        Duration::from_secs(10),
        resolve_and_validate_with(&url, &|ip| !is_forbidden_ip(ip), lookup),
    )
    .await
    .map_err(|_| RequestFailure)?
    .map_err(|_| RequestFailure)?;
    send(PinnedRequest {
        url,
        addrs,
        request,
    })
    .await
}

pub(super) fn xrpc_limit(nsid: &str) -> usize {
    if matches!(
        nsid,
        "com.atproto.server.createSession" | "com.atproto.server.refreshSession"
    ) {
        MAX_AUTH_BODY
    } else {
        MAX_RECORD_BODY
    }
}

/// Never call bytes()/text()/json() on an untrusted auth response. Testable
/// independently of sockets; a stream is stopped at the first excessive chunk.
pub(super) async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
        || response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit as u64)
    {
        return Err(RequestFailure);
    }
    let mut builder = http::Response::builder().status(response.status());
    *builder.headers_mut().ok_or(RequestFailure)? = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| RequestFailure)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(RequestFailure);
        }
        body.extend_from_slice(&chunk);
    }
    builder.body(body).map_err(|_| RequestFailure)
}

impl HttpClient for SessionHttp {
    type Error = RequestFailure;

    async fn send_http(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, Self::Error> {
        send_checked_with(
            request,
            |domain, port| async move {
                tokio::net::lookup_host((domain, port))
                    .await
                    .map(|addrs| addrs.collect())
            },
            PinnedRequest::send,
        )
        .await
    }
}

pub(super) fn expired_token(status: http::StatusCode, bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct TokenError<'a> {
        error: &'a str,
    }
    matches!(status.as_u16(), 400 | 401)
        && bytes.len() <= MAX_AUTH_BODY
        && serde_json::from_slice::<TokenError<'_>>(bytes)
            .is_ok_and(|error| error.error == "ExpiredToken")
}

pub(super) async fn send_xrpc<R>(
    http: &(impl HttpClient + Sync),
    pds: &Url,
    request: &R,
    options: &CallOptions<'_>,
    allow_expired: bool,
) -> std::result::Result<XrpcResponse<R>, RequestFailure>
where
    R: XrpcRequest + Sync,
    R::Response: Send + Sync,
{
    let mut request = build_http_request(pds, request, options).map_err(|_| RequestFailure)?;
    // The generated SDK unit request serializes as JSON null, but this
    // procedure has no input. PDS servers reject any JSON body here.
    if R::NSID == "com.atproto.server.refreshSession" {
        request.body_mut().clear();
        request.headers_mut().remove(http::header::CONTENT_TYPE);
    }
    let response = http.send_http(request).await.map_err(|_| RequestFailure)?;
    // Also enforce the cap for injected/mock HttpClient implementations.
    if response.body().len() > xrpc_limit(R::NSID) {
        return Err(RequestFailure);
    }
    // Jacquard drops the body on 401 + WWW-Authenticate. Bypass that conversion
    // ONLY for the exact XRPC expiry code, on the first authenticated attempt.
    // No headers are stripped or reinterpreted; every other response uses the
    // unchanged SDK policy (including all unrelated authentication challenges).
    if allow_expired && expired_token(response.status(), response.body()) {
        let status = response.status();
        return Ok(Response::new(response.into_body().into(), status));
    }
    process_response(response).map_err(|_| RequestFailure)
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn oversized_declared_body_is_refused_without_polling_the_stream() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let body = reqwest::Body::wrap_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(vec![b'x'; 1024])))
        }));
        let response = http::Response::builder()
            .header("content-length", MAX_AUTH_BODY + 1)
            .body(body)
            .unwrap()
            .into();
        assert!(read_limited(response, MAX_AUTH_BODY).await.is_err());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn chunked_body_is_stopped_at_limit_without_buffering_the_rest() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let body = reqwest::Body::wrap_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(vec![b'x'; 16 * 1024])))
        }));
        let response = http::Response::new(body).into();
        assert!(read_limited(response, MAX_AUTH_BODY).await.is_err());
        assert_eq!(
            polls.load(Ordering::SeqCst),
            MAX_AUTH_BODY / (16 * 1024) + 1
        );
    }

    #[tokio::test]
    async fn exact_limit_is_accepted_with_headers_unchanged() {
        let response = http::Response::builder()
            .status(401)
            .header("www-authenticate", "Bearer fixture-challenge")
            .body(vec![b'x'; MAX_AUTH_BODY])
            .unwrap()
            .into();
        let response = read_limited(response, MAX_AUTH_BODY).await.unwrap();
        assert_eq!(response.body().len(), MAX_AUTH_BODY);
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer fixture-challenge"
        );
    }
}
