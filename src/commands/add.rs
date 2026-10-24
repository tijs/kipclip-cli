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
