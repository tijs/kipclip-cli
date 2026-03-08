use miette::Result;

use crate::kipclip::display;
use crate::kipclip::pds::PdsClient;
use crate::kipclip::types::EnrichedBookmark;

/// Filter bookmarks by tag, search query
fn filter_bookmarks(
    bookmarks: Vec<EnrichedBookmark>,
    tag: Option<&str>,
    search: Option<&str>,
) -> Vec<EnrichedBookmark> {
    bookmarks
        .into_iter()
        .filter(|b| {
            if let Some(tag) = tag {
                let tag_lower = tag.to_lowercase();
                if !b.tags.iter().any(|t| t.to_lowercase() == tag_lower) {
                    return false;
                }
            }
            if let Some(query) = search {
                let q = query.to_lowercase();
                let in_title = b
                    .title
                    .as_ref()
                    .is_some_and(|t| t.to_lowercase().contains(&q));
                let in_url = b.subject.to_lowercase().contains(&q);
                let in_desc = b
                    .description
                    .as_ref()
                    .is_some_and(|d| d.to_lowercase().contains(&q));
                let in_note = b
                    .note
                    .as_ref()
                    .is_some_and(|n| n.to_lowercase().contains(&q));
                if !(in_title || in_url || in_desc || in_note) {
                    return false;
                }
            }
            true
        })
        .collect()
}

pub async fn run(
    pds: &PdsClient,
    tag: Option<&str>,
    search: Option<&str>,
    limit: Option<u32>,
    json: bool,
) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let mut filtered = filter_bookmarks(bookmarks, tag, search);

    if let Some(n) = limit {
        filtered.truncate(n as usize);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&filtered).unwrap_or_default());
    } else {
        display::print_bookmarks(&filtered);
    }

    Ok(())
}
