use miette::{IntoDiagnostic, Result};

use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;
use crate::kipclip::url::validate_http_url;

pub async fn run(pds: &PdsClient, reference: &str) -> Result<()> {
    let bookmarks = pds.fetch_bookmarks_only(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;

    validate_http_url(&bookmark.subject)?;

    println!("Opening: {}", bookmark.display_title());
    open::that(&bookmark.subject).into_diagnostic()?;
    Ok(())
}
