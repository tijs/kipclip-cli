use miette::{Result, miette};

use crate::kipclip::enrich;
use crate::kipclip::pds::PdsClient;
use crate::kipclip::types::*;
use crate::kipclip::url::validate_http_url;

/// Cached metadata is data, never a filename or an instruction to fetch a URL.
pub fn read_metadata(reader: impl std::io::Read) -> Result<UrlMetadata> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| miette!("Could not read cached metadata."))?;
    if bytes.len() > 16 * 1024 {
        return Err(miette!("Cached metadata exceeds 16 KiB."));
    }
    serde_json::from_slice(&bytes).map_err(|_| miette!("Invalid cached metadata JSON."))
}

/// The caller performs canonical live deduplication before this operation.
/// No article fetches, collection scans or optimistic success acknowledgments.
pub async fn save_verified<H: jacquard::http_client::HttpClient + Send + Sync + 'static>(
    pds: &PdsClient<H>,
    url: &str,
    tags: &[String],
    metadata: UrlMetadata,
) -> Result<EnrichedBookmark> {
    validate_http_url(url)?;
    let now = chrono::Utc::now().to_rfc3339();
    let bookmark = BookmarkRecord {
        subject: url.to_string(),
        created_at: now.clone(),
        tags: tags.to_vec(),
    };
    let created = pds
        .create_record(BOOKMARK_COLLECTION, None, &bookmark)
        .await?;
    let rkey = crate::kipclip::refs::rkey_from_uri(&created.uri);
    let annotation = AnnotationRecord {
        subject: created.uri.clone(),
        created_at: now.clone(),
        note: None,
        title: metadata.title.clone(),
        description: metadata.description.clone(),
        favicon: metadata.favicon.clone(),
        image: metadata.image.clone(),
    };
    pds.create_record(ANNOTATION_COLLECTION, Some(&rkey), &annotation)
        .await?;
    let (read_bookmark, read_annotation) = tokio::try_join!(
        pds.get_record(BOOKMARK_COLLECTION, &rkey),
        pds.get_record(ANNOTATION_COLLECTION, &rkey),
    )?;
    let read_bookmark: BookmarkRecord = serde_json::from_value(read_bookmark.value)
        .map_err(|_| miette!("Saved bookmark readback was invalid."))?;
    let read_annotation: AnnotationRecord = serde_json::from_value(read_annotation.value)
        .map_err(|_| miette!("Saved annotation readback was invalid."))?;
    if read_bookmark.subject != url
        || tags.iter().any(|tag| !read_bookmark.tags.contains(tag))
        || read_annotation.subject != created.uri
        || read_annotation.title != metadata.title
        || read_annotation.description != metadata.description
        || read_annotation.image != metadata.image
        || read_annotation.favicon != metadata.favicon
    {
        return Err(miette!(
            "Saved record verification failed; retry checks live duplicates first."
        ));
    }
    Ok(EnrichedBookmark {
        uri: created.uri,
        cid: String::new(),
        rkey,
        subject: read_bookmark.subject,
        created_at: read_bookmark.created_at,
        tags: read_bookmark.tags,
        title: read_annotation.title,
        description: read_annotation.description,
        favicon: read_annotation.favicon,
        image: read_annotation.image,
        note: read_annotation.note,
    })
}

/// Complete a partial save without creating another bookmark or overwriting
/// an existing annotation (including user notes or edits).
pub async fn resume_verified<H: jacquard::http_client::HttpClient + Send + Sync + 'static>(
    pds: &PdsClient<H>,
    url: &str,
    tags: &[String],
    metadata: UrlMetadata,
    rkey: &str,
) -> Result<EnrichedBookmark> {
    validate_http_url(url)?;
    let record = pds.get_record(BOOKMARK_COLLECTION, rkey).await?;
    let bookmark: BookmarkRecord = serde_json::from_value(record.value)
        .map_err(|_| miette!("Interrupted bookmark readback was invalid."))?;
    if bookmark.subject != url || tags.iter().any(|tag| !bookmark.tags.contains(tag)) {
        return Err(miette!(
            "Interrupted bookmark URL/tags no longer match; nothing was overwritten."
        ));
    }
    let uri = pds.record_uri(BOOKMARK_COLLECTION, rkey);
    let mut repaired = false;
    let annotation = match pds.find_record(ANNOTATION_COLLECTION, rkey).await? {
        Some(record) => record,
        None => {
            repaired = true;
            let annotation = AnnotationRecord {
                subject: uri.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                note: None,
                title: metadata.title.clone(),
                description: metadata.description.clone(),
                image: metadata.image.clone(),
                favicon: metadata.favicon.clone(),
            };
            pds.create_record(ANNOTATION_COLLECTION, Some(rkey), &annotation)
                .await?;
            pds.get_record(ANNOTATION_COLLECTION, rkey).await?
        }
    };
    let annotation: AnnotationRecord = serde_json::from_value(annotation.value)
        .map_err(|_| miette!("Interrupted annotation readback was invalid."))?;
    if annotation.subject != uri {
        return Err(miette!(
            "Interrupted annotation points at another bookmark; nothing was overwritten."
        ));
    }
    if repaired
        && (annotation.title != metadata.title
            || annotation.description != metadata.description
            || annotation.image != metadata.image
            || annotation.favicon != metadata.favicon)
    {
        return Err(miette!(
            "Repaired annotation did not match the save request."
        ));
    }
    // Re-check bookmark after any missing-sidecar repair, before confirmation.
    let final_record = pds.get_record(BOOKMARK_COLLECTION, rkey).await?;
    let final_bookmark: BookmarkRecord = serde_json::from_value(final_record.value)
        .map_err(|_| miette!("Interrupted bookmark readback was invalid."))?;
    if final_bookmark.subject != url || tags.iter().any(|tag| !final_bookmark.tags.contains(tag)) {
        return Err(miette!("Interrupted bookmark changed during verification."));
    }
    Ok(EnrichedBookmark {
        uri,
        cid: String::new(),
        rkey: rkey.to_string(),
        subject: final_bookmark.subject,
        created_at: final_bookmark.created_at,
        tags: final_bookmark.tags,
        title: annotation.title,
        description: annotation.description,
        image: annotation.image,
        favicon: annotation.favicon,
        note: annotation.note,
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_metadata_is_bounded_and_never_echoed_on_failure() {
        assert!(read_metadata(&b"{}"[..]).is_ok());
        for bytes in [
            b"fixture-private-invalid".to_vec(),
            vec![b'x'; 16 * 1024 + 1],
        ] {
            let error = read_metadata(bytes.as_slice()).unwrap_err();
            assert!(!error.to_string().contains("fixture-private"));
        }
    }
}
