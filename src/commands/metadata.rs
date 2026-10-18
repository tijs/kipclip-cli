use miette::{IntoDiagnostic, Result};

use crate::kipclip::enrich;
use crate::kipclip::types::UrlMetadata;

/// Fetch page metadata for a URL.
///
/// Read-only: no session, no PDS client, no credentials, no records written.
pub async fn run(url: &str, json: bool) -> Result<()> {
    let metadata = enrich::fetch_metadata(url).await?;
    if json {
        println!("{}", serde_json::to_string(&metadata).into_diagnostic()?);
    } else {
        print!("{}", format_human(&metadata));
    }
    Ok(())
}

/// Human-readable rendering: one `Field: value` line per extracted field.
fn format_human(metadata: &UrlMetadata) -> String {
    let mut out = String::new();
    for (label, value) in [
        ("Title", &metadata.title),
        ("Description", &metadata.description),
        ("Favicon", &metadata.favicon),
        ("Image", &metadata.image),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{label}: {value}\n"));
        }
    }
    if out.is_empty() {
        out.push_str("No metadata found.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_output_omits_missing_keys() {
        let metadata = UrlMetadata {
            title: Some("Hello".to_string()),
            description: None,
            favicon: Some("https://example.com/favicon.ico".to_string()),
            image: None,
        };
        assert_eq!(
            serde_json::to_string(&metadata).unwrap(),
            r#"{"title":"Hello","favicon":"https://example.com/favicon.ico"}"#
        );
    }

    #[test]
    fn json_output_for_empty_metadata_is_empty_object() {
        let metadata = UrlMetadata {
            title: None,
            description: None,
            favicon: None,
            image: None,
        };
        assert_eq!(serde_json::to_string(&metadata).unwrap(), "{}");
    }

    #[test]
    fn human_output_lists_present_fields() {
        let metadata = UrlMetadata {
            title: Some("Hello".to_string()),
            description: Some("Desc".to_string()),
            favicon: None,
            image: None,
        };
        let out = format_human(&metadata);
        assert!(out.contains("Title: Hello"), "{out}");
        assert!(out.contains("Description: Desc"), "{out}");
        assert!(!out.contains("Favicon"), "{out}");
    }

    #[test]
    fn human_output_for_empty_metadata() {
        let metadata = UrlMetadata {
            title: None,
            description: None,
            favicon: None,
            image: None,
        };
        assert_eq!(format_human(&metadata), "No metadata found.\n");
    }
}
