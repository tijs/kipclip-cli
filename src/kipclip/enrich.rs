use miette::{IntoDiagnostic, Result, miette};
use reqwest::header;

use crate::kipclip::types::UrlMetadata;

const MAX_TITLE_LENGTH: usize = 200;
const MAX_DESCRIPTION_LENGTH: usize = 500;
const MAX_URL_LENGTH: usize = 2000;
const TIMEOUT_SECS: u64 = 10;

/// Fetch a URL and extract metadata (title, description, favicon, og:image)
pub async fn enrich_url(url: &str) -> Result<UrlMetadata> {
    let parsed = reqwest::Url::parse(url).map_err(|e| miette!("Invalid URL: {e}"))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(miette!("Only HTTP(S) URLs are supported"));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .build()
        .into_diagnostic()?;

    let resp = client
        .get(url)
        .header(
            header::USER_AGENT,
            "kipclip-bot/1.0 (Bookmark enrichment; +https://kipclip.com)",
        )
        .send()
        .await
        .map_err(|e| miette!("Failed to fetch URL: {e}"))?;

    if !resp.status().is_success() {
        let hostname = parsed.host_str().unwrap_or(url);
        return Ok(UrlMetadata {
            title: Some(hostname.to_string()),
            description: None,
            favicon: Some(default_favicon(&parsed)),
            image: None,
        });
    }

    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("text/html") {
        let hostname = parsed.host_str().unwrap_or(url);
        return Ok(UrlMetadata {
            title: Some(hostname.to_string()),
            description: None,
            favicon: Some(default_favicon(&parsed)),
            image: None,
        });
    }

    let html = resp.text().await.into_diagnostic()?;
    Ok(parse_html_metadata(&html, &parsed))
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

fn parse_html_metadata(html: &str, url: &reqwest::Url) -> UrlMetadata {
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
    let pattern1 = format!(
        r#"(?i)<meta[^>]+{attr_name}=["']{attr_value}["'][^>]+content=["']([^"']+)["']"#
    );
    if let Some(caps) = regex_lite::Regex::new(&pattern1)
        .ok()
        .and_then(|re| re.captures(html))
    {
        return Some(caps[1].to_string());
    }

    // Try: <meta content="..." attr="value">
    let pattern2 = format!(
        r#"(?i)<meta[^>]+content=["']([^"']+)["'][^>]+{attr_name}=["']{attr_value}["']"#
    );
    if let Some(caps) = regex_lite::Regex::new(&pattern2)
        .ok()
        .and_then(|re| re.captures(html))
    {
        return Some(caps[1].to_string());
    }

    None
}
