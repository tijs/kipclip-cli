use miette::{Result, miette};

use crate::kipclip::types::EnrichedBookmark;

/// Resolve a bookmark reference (rkey prefix) to a full bookmark.
/// Requires at least 4 characters for prefix matching.
pub fn resolve_ref<'a>(
    prefix: &str,
    bookmarks: &'a [EnrichedBookmark],
) -> Result<&'a EnrichedBookmark> {
    if prefix.len() < 4 {
        return Err(miette!("Bookmark ref must be at least 4 characters"));
    }

    let matches: Vec<&EnrichedBookmark> = bookmarks
        .iter()
        .filter(|b| b.rkey.starts_with(prefix))
        .collect();

    match matches.len() {
        0 => Err(miette!("No bookmark found matching ref '{prefix}'")),
        1 => Ok(matches[0]),
        n => Err(miette!(
            "Ambiguous ref '{prefix}' matches {n} bookmarks. Use a longer prefix."
        )),
    }
}

/// Extract rkey from an AT URI (last path segment)
pub fn rkey_from_uri(uri: &str) -> String {
    uri.split('/').next_back().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bookmark(rkey: &str, subject: &str) -> EnrichedBookmark {
        EnrichedBookmark {
            uri: format!("at://did:plc:test/community.lexicon.bookmarks.bookmark/{rkey}"),
            cid: "bafytest".to_string(),
            rkey: rkey.to_string(),
            subject: subject.to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            tags: vec![],
            title: None,
            description: None,
            favicon: None,
            image: None,
            note: None,
        }
    }

    #[test]
    fn rkey_from_uri_extracts_last_segment() {
        let uri = "at://did:plc:abc123/community.lexicon.bookmarks.bookmark/3lf5abc";
        assert_eq!(rkey_from_uri(uri), "3lf5abc");
    }

    #[test]
    fn rkey_from_uri_empty_string() {
        assert_eq!(rkey_from_uri(""), "");
    }

    #[test]
    fn resolve_ref_exact_match() {
        let bookmarks = vec![
            make_bookmark("3lf5abcd", "https://example.com"),
            make_bookmark("3lf5wxyz", "https://other.com"),
        ];
        let result = resolve_ref("3lf5abcd", &bookmarks).unwrap();
        assert_eq!(result.subject, "https://example.com");
    }

    #[test]
    fn resolve_ref_prefix_match() {
        let bookmarks = vec![
            make_bookmark("3lf5abcd", "https://example.com"),
            make_bookmark("3lf5wxyz", "https://other.com"),
        ];
        let result = resolve_ref("3lf5a", &bookmarks).unwrap();
        assert_eq!(result.rkey, "3lf5abcd");
    }

    #[test]
    fn resolve_ref_too_short() {
        let bookmarks = vec![make_bookmark("3lf5abcd", "https://example.com")];
        let result = resolve_ref("3lf", &bookmarks);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_ref_no_match() {
        let bookmarks = vec![make_bookmark("3lf5abcd", "https://example.com")];
        let result = resolve_ref("9999", &bookmarks);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_ref_ambiguous() {
        let bookmarks = vec![
            make_bookmark("3lf5abcd", "https://example.com"),
            make_bookmark("3lf5abef", "https://other.com"),
        ];
        let result = resolve_ref("3lf5ab", &bookmarks);
        assert!(result.is_err());
    }
}
