use miette::{IntoDiagnostic, Result};

use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;

pub async fn run(pds: &PdsClient, reference: &str) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;
    let title = bookmark.title.as_deref().unwrap_or(&bookmark.subject);
    println!("Opening: {title}");
    open::that(&bookmark.subject).into_diagnostic()?;
    Ok(())
}
