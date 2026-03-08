use miette::Result;

use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;
use crate::kipclip::types::*;

pub async fn run(pds: &PdsClient, reference: &str, remove_tags: &[String]) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;

    // Remove specified tags (case-insensitive)
    let tags: Vec<String> = bookmark
        .tags
        .iter()
        .filter(|t| {
            !remove_tags
                .iter()
                .any(|r| r.to_lowercase() == t.to_lowercase())
        })
        .cloned()
        .collect();

    let record = pds.get_record(BOOKMARK_COLLECTION, &bookmark.rkey).await?;
    let mut value = record.value;
    value["tags"] = serde_json::json!(tags);

    pds.put_record(BOOKMARK_COLLECTION, &bookmark.rkey, value)
        .await?;

    let title = bookmark.title.as_deref().unwrap_or(&bookmark.subject);
    println!("Updated tags on: {title}");
    if tags.is_empty() {
        println!("Tags: (none)");
    } else {
        println!("Tags: {}", tags.join(", "));
    }
    Ok(())
}
