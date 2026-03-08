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
        println!(
            "{}",
            serde_json::to_string_pretty(&filtered).unwrap_or_default()
        );
    } else {
        display::print_bookmarks(&filtered);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bookmark(subject: &str, title: Option<&str>, tags: &[&str]) -> EnrichedBookmark {
        EnrichedBookmark {
            uri: "at://did:plc:test/community.lexicon.bookmarks.bookmark/abc123".to_string(),
            cid: "bafytest".to_string(),
            rkey: "abc123".to_string(),
            subject: subject.to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            title: title.map(|t| t.to_string()),
            description: None,
            favicon: None,
            image: None,
            note: None,
        }
    }

    fn make_bookmark_with_note(subject: &str, note: &str) -> EnrichedBookmark {
        let mut b = make_bookmark(subject, None, &[]);
        b.note = Some(note.to_string());
        b
    }

    fn make_bookmark_with_desc(subject: &str, desc: &str) -> EnrichedBookmark {
        let mut b = make_bookmark(subject, None, &[]);
        b.description = Some(desc.to_string());
        b
    }

    #[test]
    fn no_filters_returns_all() {
        let bookmarks = vec![
            make_bookmark("https://a.com", Some("A"), &[]),
            make_bookmark("https://b.com", Some("B"), &[]),
        ];
        let result = filter_bookmarks(bookmarks, None, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_by_tag() {
        let bookmarks = vec![
            make_bookmark("https://a.com", Some("A"), &["rust"]),
            make_bookmark("https://b.com", Some("B"), &["go"]),
            make_bookmark("https://c.com", Some("C"), &["rust", "web"]),
        ];
        let result = filter_bookmarks(bookmarks, Some("rust"), None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].subject, "https://a.com");
        assert_eq!(result[1].subject, "https://c.com");
    }

    #[test]
    fn filter_by_tag_case_insensitive() {
        let bookmarks = vec![make_bookmark("https://a.com", Some("A"), &["Rust"])];
        let result = filter_bookmarks(bookmarks, Some("rust"), None);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn search_matches_title() {
        let bookmarks = vec![
            make_bookmark("https://a.com", Some("Rust Guide"), &[]),
            make_bookmark("https://b.com", Some("Go Guide"), &[]),
        ];
        let result = filter_bookmarks(bookmarks, None, Some("rust"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].subject, "https://a.com");
    }

    #[test]
    fn search_matches_url() {
        let bookmarks = vec![
            make_bookmark("https://rust-lang.org", Some("Home"), &[]),
            make_bookmark("https://golang.org", Some("Home"), &[]),
        ];
        let result = filter_bookmarks(bookmarks, None, Some("rust"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn search_matches_description() {
        let bookmarks = vec![make_bookmark_with_desc(
            "https://a.com",
            "A guide to Rust programming",
        )];
        let result = filter_bookmarks(bookmarks, None, Some("rust"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn search_matches_note() {
        let bookmarks = vec![make_bookmark_with_note(
            "https://a.com",
            "Read this rust book",
        )];
        let result = filter_bookmarks(bookmarks, None, Some("rust"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn search_is_case_insensitive() {
        let bookmarks = vec![make_bookmark("https://a.com", Some("RUST Guide"), &[])];
        let result = filter_bookmarks(bookmarks, None, Some("rust"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn combined_tag_and_search() {
        let bookmarks = vec![
            make_bookmark("https://a.com", Some("Rust Guide"), &["reading"]),
            make_bookmark("https://b.com", Some("Rust Ref"), &["reference"]),
            make_bookmark("https://c.com", Some("Go Guide"), &["reading"]),
        ];
        let result = filter_bookmarks(bookmarks, Some("reading"), Some("rust"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].subject, "https://a.com");
    }

    #[test]
    fn search_no_match_returns_empty() {
        let bookmarks = vec![make_bookmark("https://a.com", Some("Hello"), &[])];
        let result = filter_bookmarks(bookmarks, None, Some("nonexistent"));
        assert!(result.is_empty());
    }
}
