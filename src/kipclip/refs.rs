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
    uri.split('/').last().unwrap_or("").to_string()
}
