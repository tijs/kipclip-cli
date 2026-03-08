use miette::{Result, miette};

/// Validate that a string is a valid HTTP(S) URL.
/// Returns the parsed URL on success.
pub fn validate_http_url(url: &str) -> Result<reqwest::Url> {
    let parsed = reqwest::Url::parse(url).map_err(|e| miette!("Invalid URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(miette!("Only HTTP(S) URLs are supported"));
    }
    Ok(parsed)
}
