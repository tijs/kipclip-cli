use miette::Result;

use crate::kipclip::pds::PdsClient;

/// Search is an alias for list --search
pub async fn run(pds: &PdsClient, query: &str, json: bool) -> Result<()> {
    crate::commands::list::run(pds, None, Some(query), None, json).await
}
