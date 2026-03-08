use miette::Result;
use owo_colors::OwoColorize;

use crate::kipclip::pds::PdsClient;

pub async fn run(pds: &PdsClient, json: bool) -> Result<()> {
    // Only need bookmark tags, skip annotation fetch
    let bookmarks = pds.fetch_bookmarks_only(None).await?;

    // Count bookmarks per tag
    let mut tag_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for bookmark in &bookmarks {
        for tag in &bookmark.tags {
            *tag_counts.entry(tag.clone()).or_default() += 1;
        }
    }

    if json {
        let tags: Vec<serde_json::Value> = tag_counts
            .iter()
            .map(|(tag, count)| {
                serde_json::json!({
                    "tag": tag,
                    "count": count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&tags).unwrap_or_default()
        );
    } else if tag_counts.is_empty() {
        println!("No tags found.");
    } else {
        for (tag, count) in &tag_counts {
            println!("  {} {}", tag.green(), format!("({count})").dimmed());
        }
    }

    Ok(())
}
