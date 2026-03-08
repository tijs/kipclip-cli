use miette::{Result, miette};

use crate::kipclip::enrich;
use crate::kipclip::pds::PdsClient;
use crate::kipclip::types::*;
use crate::kipclip::url::validate_http_url;

pub async fn run(pds: &PdsClient, url: &str, tags: &[String]) -> Result<()> {
    validate_http_url(url)?;

    // Check for duplicates (only need bookmark subjects, skip annotation fetch)
    let existing = pds.fetch_bookmarks_only(None).await?;
    if existing.iter().any(|b| b.subject == url) {
        return Err(miette!("Bookmark already exists for {url}"));
    }

    // Enrich the URL
    print!("Enriching URL…");
    let metadata = match enrich::enrich_url(url).await {
        Ok(m) => {
            println!(" done.");
            m
        }
        Err(e) => {
            println!(" failed ({e}), continuing without metadata.");
            UrlMetadata {
                title: None,
                description: None,
                favicon: None,
                image: None,
            }
        }
    };

    let now = chrono::Utc::now().to_rfc3339();

    // Create bookmark record
    let bookmark = BookmarkRecord {
        subject: url.to_string(),
        created_at: now.clone(),
        tags: tags.to_vec(),
    };
    let bookmark_resp = pds
        .create_record(BOOKMARK_COLLECTION, None, &bookmark)
        .await?;

    // Create annotation sidecar with same rkey
    let bookmark_rkey = crate::kipclip::refs::rkey_from_uri(&bookmark_resp.uri);
    let annotation = AnnotationRecord {
        subject: bookmark_resp.uri.clone(),
        created_at: now,
        note: None,
        title: metadata.title.clone(),
        description: metadata.description,
        favicon: metadata.favicon,
        image: metadata.image,
    };
    pds.create_record(ANNOTATION_COLLECTION, Some(&bookmark_rkey), &annotation)
        .await?;

    let title = metadata.title.as_deref().unwrap_or(url);
    println!("Added: {title}");
    if !tags.is_empty() {
        println!("Tags: {}", tags.join(", "));
    }

    Ok(())
}
