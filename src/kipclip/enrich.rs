use miette::{IntoDiagnostic, Result, miette};

use crate::kipclip::config;
use crate::kipclip::types::UrlMetadata;

/// Call the kipclip appview /api/enrich endpoint
pub async fn enrich_url(url: &str) -> Result<UrlMetadata> {
    let appview = config::appview_url();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{appview}/api/enrich"))
        .json(&serde_json::json!({ "url": url }))
        .send()
        .await
        .into_diagnostic()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(miette!("Enrichment failed ({status}): {body}"));
    }

    resp.json::<UrlMetadata>().await.into_diagnostic()
}
