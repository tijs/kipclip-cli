//! Bounded, credential-free app-login discovery. Jacquard 0.9's HTTP resolver
//! buffers unbounded bodies and get_text panics on non-200 2xx/3xx statuses.
//! Use Jacquard ONLY for DNS TXT (no HTTP steps); retain its default DNS ->
//! well-known -> public resolveHandle order and native PLC/did:web document URLs.

use std::net::SocketAddr;
use std::time::Duration;

use jacquard::IntoStatic;
use jacquard::http_client::HttpClient;
use jacquard::types::string::{Did, Handle};
use jacquard_identity::JacquardResolver;
use jacquard_identity::resolver::{
    DidDocResponse, HandleStep, IdentityError, IdentityResolver, ResolverOptions,
};
use miette::Result;
use url::{Host, Url};

use super::super::auth::RequestFailure;
use super::super::fetch::{is_forbidden_ip, resolve_and_validate_with};
use super::transport::{MAX_AUTH_BODY, private_client, private_client_builder, read_limited};

const MAX_REDIRECTS: usize = 3;

pub(super) struct DiscoveryHttp;

/// One approved discovery hop. Deliberately cannot carry caller headers or a
/// body. Keep the original hostname for TLS/SNI/Host, not a rewritten IP URL.
struct PinnedDiscovery {
    url: Url,
    addrs: Vec<SocketAddr>,
}

impl PinnedDiscovery {
    fn client_builder(&self) -> reqwest::ClientBuilder {
        let builder = private_client_builder();
        match self.url.host() {
            Some(Host::Domain(domain)) => builder.resolve_to_addrs(domain, &self.addrs),
            // Literals were checked directly; reqwest's DNS overrides do not
            // apply to them, and there is no second DNS lookup to pin.
            _ => builder,
        }
    }

    async fn send(self) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure> {
        let client = self.client_builder().build().map_err(|_| RequestFailure)?;
        self.send_using(client).await
    }

    async fn send_using(
        self,
        client: reqwest::Client,
    ) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure> {
        // Fresh direct client for EVERY hop: no pooled connection, cookies,
        // caller headers, auth, proxy DNS, or automatic redirects can bypass
        // the preflight. TLS certificate/hostname verification stays enabled.
        let response = client
            .get(self.url)
            .send()
            .await
            .map_err(|_| RequestFailure)?;
        read_limited(response, MAX_AUTH_BODY).await
    }
}

/// Injectable DNS and executor exercise the production preflight offline.
/// Every discovery source and every manually followed redirect passes here.
async fn send_checked_with<L, F, S, O>(
    request: http::Request<Vec<u8>>,
    lookup: L,
    send: S,
) -> std::result::Result<http::Response<Vec<u8>>, RequestFailure>
where
    L: FnOnce(String, u16) -> F,
    F: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
    S: FnOnce(PinnedDiscovery) -> O,
    O: std::future::Future<Output = std::result::Result<http::Response<Vec<u8>>, RequestFailure>>,
{
    if request.method() != http::Method::GET
        || !request.body().is_empty()
        || [
            http::header::AUTHORIZATION,
            http::header::PROXY_AUTHORIZATION,
            http::header::COOKIE,
        ]
        .iter()
        .any(|header| request.headers().contains_key(header))
    {
        return Err(RequestFailure);
    }
    let url = Url::parse(&request.uri().to_string()).map_err(|_| RequestFailure)?;
    if !valid_url(&url) {
        return Err(RequestFailure);
    }
    // Fail closed for empty/failed/mixed DNS answers. Resolve afresh on every
    // hop, even for a relative redirect back to the same hostname. Discard raw
    // lookup errors/URLs so diagnostics cannot expose caller input.
    let addrs = tokio::time::timeout(
        Duration::from_secs(10),
        resolve_and_validate_with(&url, &|ip| !is_forbidden_ip(ip), lookup),
    )
    .await
    .map_err(|_| RequestFailure)?
    .map_err(|_| RequestFailure)?;
    send(PinnedDiscovery { url, addrs }).await
}

impl HttpClient for DiscoveryHttp {
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
            PinnedDiscovery::send,
        )
        .await
    }
}

pub(super) struct DiscoveryResolver<T = DiscoveryHttp> {
    pub(super) http: T,
    pub(super) dns: Option<JacquardResolver>,
    pub(super) opts: ResolverOptions,
}

impl DiscoveryResolver {
    pub(super) fn new() -> Result<Self> {
        let dns_options = ResolverOptions {
            handle_order: vec![HandleStep::DnsTxt],
            did_order: vec![],
            public_fallback_for_handle: false,
            ..Default::default()
        };
        Ok(Self {
            http: DiscoveryHttp,
            dns: Some(JacquardResolver::new_dns(private_client()?, dns_options)),
            opts: Default::default(),
        })
    }
}

fn invalid() -> IdentityError {
    IdentityError::invalid_well_known()
}

fn valid_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn exact_did(raw: &str) -> std::result::Result<Did<'static>, RequestFailure> {
    let did = Did::new_owned(raw).map_err(|_| RequestFailure)?;
    if did.as_str() != raw {
        return Err(RequestFailure);
    }
    Ok(did)
}

fn document_url(did: &Did<'_>) -> std::result::Result<Url, RequestFailure> {
    if did.as_str().starts_with("did:plc:") {
        let mut url = Url::parse("https://plc.directory/").map_err(|_| RequestFailure)?;
        url.path_segments_mut()
            .map_err(|_| RequestFailure)?
            .push(did.as_str());
        return Ok(url);
    }
    let rest = did
        .as_str()
        .strip_prefix("did:web:")
        .ok_or(RequestFailure)?;
    let mut parts = rest.split(':');
    let host = percent_encoding::percent_decode_str(parts.next().ok_or(RequestFailure)?)
        .decode_utf8()
        .map_err(|_| RequestFailure)?;
    let mut url = Url::parse(&format!("https://{host}/")).map_err(|_| RequestFailure)?;
    if !valid_url(&url) || url.path() != "/" || url.query().is_some() {
        return Err(RequestFailure);
    }
    let path: Vec<_> = parts.collect();
    {
        let mut segments = url.path_segments_mut().map_err(|_| RequestFailure)?;
        if path.is_empty() {
            segments.push(".well-known");
        }
        for part in path {
            let part = percent_encoding::percent_decode_str(part)
                .decode_utf8()
                .map_err(|_| RequestFailure)?;
            if part.is_empty() || part == "." || part == ".." {
                return Err(RequestFailure);
            }
            segments.push(&part);
        }
        segments.push("did.json");
    }
    Ok(url)
}

impl<T: HttpClient + Sync> DiscoveryResolver<T> {
    async fn get(&self, mut url: Url) -> std::result::Result<Vec<u8>, RequestFailure> {
        for redirect in 0..=MAX_REDIRECTS {
            if !valid_url(&url) {
                return Err(RequestFailure);
            }
            let request = http::Request::get(url.as_str())
                .body(Vec::new())
                .map_err(|_| RequestFailure)?;
            let response = self
                .http
                .send_http(request)
                .await
                .map_err(|_| RequestFailure)?;
            if response.body().len() > MAX_AUTH_BODY {
                return Err(RequestFailure);
            }
            match response.status().as_u16() {
                200 => return Ok(response.into_body()),
                301 | 302 | 303 | 307 | 308 if redirect < MAX_REDIRECTS => {
                    let location = response
                        .headers()
                        .get(http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .ok_or(RequestFailure)?;
                    url = url.join(location).map_err(|_| RequestFailure)?;
                }
                // Including 204 and redirects without Location: error, not an
                // error_for_status().unwrap_err() panic, and never credentials.
                _ => return Err(RequestFailure),
            }
        }
        Err(RequestFailure)
    }
}

impl<T: HttpClient + Sync> IdentityResolver for DiscoveryResolver<T> {
    fn options(&self) -> &ResolverOptions {
        &self.opts
    }

    async fn resolve_handle(
        &self,
        handle: &Handle<'_>,
    ) -> std::result::Result<Did<'static>, IdentityError> {
        if let Some(dns) = &self.dns {
            if let Ok(did) = dns.resolve_handle(handle).await {
                return Ok(did);
            }
        }
        let url = Url::parse(&format!(
            "https://{}/.well-known/atproto-did",
            handle.as_str()
        ))
        .map_err(|_| invalid())?;
        if let Ok(bytes) = self.get(url).await {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if let Some(line) = text.lines().find(|line| !line.trim().is_empty()) {
                    if let Ok(did) = exact_did(line.trim()) {
                        return Ok(did);
                    }
                }
            }
        }
        let mut url =
            Url::parse("https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle")
                .map_err(|_| invalid())?;
        url.query_pairs_mut().append_pair("handle", handle.as_str());
        #[derive(serde::Deserialize)]
        struct ResolvedHandle {
            did: String,
        }
        let bytes = self.get(url).await.map_err(|_| invalid())?;
        let reply: ResolvedHandle = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        exact_did(&reply.did).map_err(|_| invalid())
    }

    async fn resolve_did_doc(
        &self,
        did: &Did<'_>,
    ) -> std::result::Result<DidDocResponse, IdentityError> {
        let url = document_url(did).map_err(|_| invalid())?;
        let bytes = self.get(url).await.map_err(|_| invalid())?;
        // Preserve the original document bytes. No typed parse/normalization or
        // synthetic mini-doc conversion before resolve_account's exact checks.
        Ok(DidDocResponse {
            buffer: bytes.into(),
            status: http::StatusCode::OK,
            requested: Some(did.clone().into_static()),
        })
    }
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod routing_tests;
