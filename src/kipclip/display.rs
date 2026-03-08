use owo_colors::OwoColorize;
use unicode_width::UnicodeWidthStr;

use crate::kipclip::types::EnrichedBookmark;

/// Truncate a string to a max display width, appending "…" if truncated
fn truncate(s: &str, max_width: usize) -> String {
    if s.width() <= max_width {
        return s.to_string();
    }
    let mut result = String::new();
    let mut width = 0;
    for ch in s.chars() {
        let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + ch_width + 1 > max_width {
            result.push('…');
            break;
        }
        result.push(ch);
        width += ch_width;
    }
    result
}

/// Display bookmarks as a formatted table
pub fn print_bookmarks(bookmarks: &[EnrichedBookmark]) {
    if bookmarks.is_empty() {
        println!("No bookmarks found.");
        return;
    }

    // Get terminal width, default to 100
    let term_width = terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(100);

    // Column widths: ref(8) + title(dynamic) + url(dynamic) + tags(20) + gaps(6)
    let ref_width = 8;
    let tags_width = 20;
    let fixed = ref_width + tags_width + 8; // 8 for separators/padding
    let remaining = term_width.saturating_sub(fixed);
    let title_width = remaining * 2 / 3;
    let url_width = remaining / 3;

    for bookmark in bookmarks {
        let ref_str = &bookmark.rkey[..bookmark.rkey.len().min(ref_width)];
        let title = bookmark
            .title
            .as_deref()
            .unwrap_or(&bookmark.subject);
        let url = &bookmark.subject;
        let tags = if bookmark.tags.is_empty() {
            String::new()
        } else {
            bookmark.tags.join(", ")
        };

        println!(
            "{}  {}  {}  {}",
            truncate(ref_str, ref_width).dimmed(),
            truncate(title, title_width).bold(),
            truncate(url, url_width).blue(),
            truncate(&tags, tags_width).green(),
        );
    }
}

/// Print a single bookmark in detail
pub fn print_bookmark_detail(bookmark: &EnrichedBookmark) {
    println!("{} {}", "Ref:".dimmed(), bookmark.rkey.dimmed());
    if let Some(title) = &bookmark.title {
        println!("{} {}", "Title:".dimmed(), title.bold());
    }
    println!("{} {}", "URL:".dimmed(), bookmark.subject.blue());
    if let Some(desc) = &bookmark.description {
        println!("{} {}", "Description:".dimmed(), desc);
    }
    if !bookmark.tags.is_empty() {
        println!("{} {}", "Tags:".dimmed(), bookmark.tags.join(", ").green());
    }
    if let Some(note) = &bookmark.note {
        println!("{} {}", "Note:".dimmed(), note);
    }
    println!("{} {}", "Created:".dimmed(), bookmark.created_at);
}
