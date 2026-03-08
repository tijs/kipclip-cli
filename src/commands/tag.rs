use miette::Result;

use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;
use crate::kipclip::types::*;

pub async fn run(pds: &PdsClient, reference: &str, new_tags: &[String]) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;

    // Merge existing + new tags (deduplicate, case-insensitive)
    let mut tags = bookmark.tags.clone();
    for tag in new_tags {
        let tag_lower = tag.to_lowercase();
        if !tags.iter().any(|t| t.to_lowercase() == tag_lower) {
            tags.push(tag.clone());
        }
    }

    // Get current record and update tags
    let record = pds.get_record(BOOKMARK_COLLECTION, &bookmark.rkey).await?;
    let mut value = record.value;
    value["tags"] = serde_json::json!(tags);

    pds.put_record(BOOKMARK_COLLECTION, &bookmark.rkey, value)
        .await?;

    let title = bookmark.title.as_deref().unwrap_or(&bookmark.subject);
    println!("Updated tags on: {title}");
    println!("Tags: {}", tags.join(", "));
    Ok(())
}
