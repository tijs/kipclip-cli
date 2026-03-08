use miette::Result;

use crate::kipclip::display;
use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;
use crate::kipclip::types::*;

pub async fn run(pds: &PdsClient, reference: &str, force: bool) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;

    if !force {
        display::print_bookmark_detail(bookmark);
        println!("\nUse --force to confirm deletion.");
        return Ok(());
    }

    let rkey = &bookmark.rkey;

    // Delete bookmark record
    pds.delete_record(BOOKMARK_COLLECTION, rkey).await?;

    // Delete annotation sidecar (same rkey)
    let _ = pds.delete_record(ANNOTATION_COLLECTION, rkey).await;

    let title = bookmark.title.as_deref().unwrap_or(&bookmark.subject);
    println!("Deleted: {title}");
    Ok(())
}
