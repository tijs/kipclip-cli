use miette::{Result, miette};

use crate::kipclip::fetch;
use crate::kipclip::types::UrlMetadata;
use crate::kipclip::url::validate_http_url;

const MAX_TITLE_LENGTH: usize = 200;
const MAX_DESCRIPTION_LENGTH: usize = 500;
const MAX_URL_LENGTH: usize = 2000;

/// Fetch a URL and extract metadata (title, description, favicon, og:image).
///
/// Best-effort for `kip add`: HTTP error responses and non-HTML pages fall
/// back to the hostname and default favicon. Transport, validation, and
/// safety failures are returned as errors.
pub async fn enrich_url(url: &str) -> Result<UrlMetadata> {
    let parsed = validate_http_url(url)?;
    let page = fetch::fetch_url(url).await?;
    match page.html {
        Some(html) => Ok(parse_html_metadata(&html, &page.final_url)),
        None => Ok(hostname_fallback(&parsed)),
    }
}

/// Fetch metadata for `url` for the read-only `kip metadata` command.
///
/// No fallback: an HTTP error status is an error, and a non-HTML response
/// yields empty metadata. Never touches the session or the PDS.
pub async fn fetch_metadata(url: &str) -> Result<UrlMetadata> {
    let page = fetch::fetch_url(url).await?;
    if !page.status.is_success() {
        return Err(miette!("HTTP {} for {url}", page.status.as_u16()));
    }
    match page.html {
        Some(html) => Ok(parse_html_metadata(&html, &page.final_url)),
        None => Ok(empty_metadata()),
    }
}

fn empty_metadata() -> UrlMetadata {
    UrlMetadata {
        title: None,
        description: None,
        favicon: None,
        image: None,
    }
}

/// Fallback for pages that cannot be fetched or parsed: the hostname as title
/// and the site's default favicon path.
fn hostname_fallback(url: &reqwest::Url) -> UrlMetadata {
    UrlMetadata {
        title: Some(
            url.host_str()
                .map(|h| h.to_string())
                .unwrap_or_else(|| url.to_string()),
        ),
        description: None,
        favicon: Some(default_favicon(url)),
        image: None,
    }
}

fn default_favicon(url: &reqwest::Url) -> String {
    format!("{}/favicon.ico", url.origin().ascii_serialization())
}

fn sanitize_text(text: &str, max_len: usize) -> String {
    text.trim()
        .replace(|c: char| c.is_control(), "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_len)
        .collect()
}

fn resolve_url(href: &str, base: &reqwest::Url) -> Option<String> {
    let resolved = base.join(href).ok()?;
    if !matches!(resolved.scheme(), "http" | "https") {
        return None;
    }
    let s = resolved.to_string();
    if s.len() > MAX_URL_LENGTH {
        return None;
    }
    Some(s)
}

pub(crate) fn parse_html_metadata(html: &str, url: &reqwest::Url) -> UrlMetadata {
    let mut metadata = UrlMetadata {
        title: None,
        description: None,
        favicon: None,
        image: None,
    };

    // Title: <title> tag
    if let Some(caps) = regex_lite::Regex::new(r"(?i)<title[^>]*>([^<]+)</title>")
        .ok()
        .and_then(|re| re.captures(html))
    {
        metadata.title = Some(sanitize_text(&caps[1], MAX_TITLE_LENGTH));
    }

    // Fallback: og:title
    if metadata.title.is_none() {
        metadata.title = extract_meta_content(html, "property", "og:title")
            .map(|s| sanitize_text(&s, MAX_TITLE_LENGTH));
    }

    // Description: <meta name="description">
    metadata.description = extract_meta_content(html, "name", "description")
        .map(|s| sanitize_text(&s, MAX_DESCRIPTION_LENGTH));

    // Fallback: og:description
    if metadata.description.is_none() {
        metadata.description = extract_meta_content(html, "property", "og:description")
            .map(|s| sanitize_text(&s, MAX_DESCRIPTION_LENGTH));
    }

    // Favicon: <link rel="icon" href="...">
    if let Some(caps) = regex_lite::Regex::new(
        r#"(?i)<link[^>]+rel=["'](?:icon|shortcut icon)["'][^>]+?href=["']([^"']+)["']"#,
    )
    .ok()
    .and_then(|re| re.captures(html))
    {
        metadata.favicon = resolve_url(&caps[1], url);
    }
    if metadata.favicon.is_none() {
        metadata.favicon = Some(default_favicon(url));
    }

    // Image: og:image
    if let Some(img) = extract_meta_content(html, "property", "og:image") {
        metadata.image = resolve_url(&img, url);
    }

    // Fallback: twitter:image
    if metadata.image.is_none() {
        if let Some(img) = extract_meta_content(html, "name", "twitter:image") {
            metadata.image = resolve_url(&img, url);
        }
    }

    // Fallback title: hostname
    if metadata.title.is_none() {
        metadata.title = url.host_str().map(|h| h.to_string());
    }

    metadata
}

/// Extract content from <meta> tag matching attr_name=attr_value
fn extract_meta_content(html: &str, attr_name: &str, attr_value: &str) -> Option<String> {
    // Try: <meta attr="value" content="...">
    let pattern1 =
        format!(r#"(?i)<meta[^>]+{attr_name}=["']{attr_value}["'][^>]+content=["']([^"']+)["']"#);
    if let Some(caps) = regex_lite::Regex::new(&pattern1)
        .ok()
        .and_then(|re| re.captures(html))
    {
        return Some(caps[1].to_string());
    }

    // Try: <meta content="..." attr="value">
    let pattern2 =
        format!(r#"(?i)<meta[^>]+content=["']([^"']+)["'][^>]+{attr_name}=["']{attr_value}["']"#);
    if let Some(caps) = regex_lite::Regex::new(&pattern2)
        .ok()
        .and_then(|re| re.captures(html))
    {
        return Some(caps[1].to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_title_from_html() {
        let html = "<html><head><title>Hello World</title></head></html>";
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.title.as_deref(), Some("Hello World"));
    }

    #[test]
    fn parse_og_title_fallback() {
        let html = r#"<html><head><meta property="og:title" content="OG Title"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.title.as_deref(), Some("OG Title"));
    }

    #[test]
    fn title_tag_takes_precedence_over_og() {
        let html = r#"<html><head>
            <title>Page Title</title>
            <meta property="og:title" content="OG Title">
        </head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.title.as_deref(), Some("Page Title"));
    }

    #[test]
    fn parse_description() {
        let html = r#"<html><head><meta name="description" content="A great page"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.description.as_deref(), Some("A great page"));
    }

    #[test]
    fn parse_og_description_fallback() {
        let html =
            r#"<html><head><meta property="og:description" content="OG desc"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.description.as_deref(), Some("OG desc"));
    }

    #[test]
    fn parse_favicon_link() {
        let html = r#"<html><head><link rel="icon" href="/favicon.png"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(
            meta.favicon.as_deref(),
            Some("https://example.com/favicon.png")
        );
    }

    #[test]
    fn default_favicon_when_no_link() {
        let html = "<html><head><title>Test</title></head></html>";
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(
            meta.favicon.as_deref(),
            Some("https://example.com/favicon.ico")
        );
    }

    #[test]
    fn parse_og_image() {
        let html = r#"<html><head><meta property="og:image" content="https://img.example.com/pic.jpg"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(
            meta.image.as_deref(),
            Some("https://img.example.com/pic.jpg")
        );
    }

    #[test]
    fn parse_twitter_image_fallback() {
        let html = r#"<html><head><meta name="twitter:image" content="https://img.example.com/tw.jpg"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(
            meta.image.as_deref(),
            Some("https://img.example.com/tw.jpg")
        );
    }

    #[test]
    fn resolve_relative_og_image() {
        let html =
            r#"<html><head><meta property="og:image" content="/images/pic.jpg"></head></html>"#;
        let url = reqwest::Url::parse("https://example.com/page").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(
            meta.image.as_deref(),
            Some("https://example.com/images/pic.jpg")
        );
    }

    #[test]
    fn hostname_fallback_title() {
        let html = "<html><head></head></html>";
        let url = reqwest::Url::parse("https://example.com").unwrap();
        let meta = parse_html_metadata(html, &url);
        assert_eq!(meta.title.as_deref(), Some("example.com"));
    }

    #[test]
    fn sanitize_text_collapses_whitespace() {
        assert_eq!(sanitize_text("  hello   world  ", 100), "hello world");
    }

    #[test]
    fn sanitize_text_truncates() {
        assert_eq!(sanitize_text("hello world", 5), "hello");
    }

    #[test]
    fn sanitize_text_strips_control_chars() {
        assert_eq!(sanitize_text("hello\x00world", 100), "helloworld");
    }

    #[test]
    fn resolve_url_rejects_non_http() {
        let base = reqwest::Url::parse("https://example.com").unwrap();
        assert!(resolve_url("javascript:alert(1)", &base).is_none());
    }

    #[test]
    fn resolve_url_resolves_relative() {
        let base = reqwest::Url::parse("https://example.com/page").unwrap();
        assert_eq!(
            resolve_url("/img.png", &base).as_deref(),
            Some("https://example.com/img.png")
        );
    }

    #[test]
    fn resolve_url_rejects_too_long() {
        let base = reqwest::Url::parse("https://example.com").unwrap();
        let long_path = "/".to_string() + &"a".repeat(MAX_URL_LENGTH);
        assert!(resolve_url(&long_path, &base).is_none());
    }

    #[test]
    fn hostname_fallback_uses_host_and_default_favicon() {
        let url = reqwest::Url::parse("https://example.com/page").unwrap();
        let meta = hostname_fallback(&url);
        assert_eq!(meta.title.as_deref(), Some("example.com"));
        assert_eq!(
            meta.favicon.as_deref(),
            Some("https://example.com/favicon.ico")
        );
        assert!(meta.description.is_none());
        assert!(meta.image.is_none());
    }

    #[tokio::test]
    async fn fetch_metadata_rejects_invalid_urls() {
        for url in ["not a url", "ftp://example.com/x", "file:///etc/passwd"] {
            assert!(fetch_metadata(url).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn fetch_metadata_refuses_local_and_private_targets() {
        for url in [
            "http://127.0.0.1:9/",
            "http://localhost:9/",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/",
        ] {
            let err = fetch_metadata(url).await.unwrap_err();
            assert!(err.to_string().contains("Refusing"), "{url}: {err}");
        }
    }
}
