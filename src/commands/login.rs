use miette::Result;

use crate::kipclip::auth;

pub async fn run(handle: &str) -> Result<()> {
    println!("Opening browser for AT Protocol login…");
    let info = auth::login(handle).await?;
    println!("Logged in as {} ({})", info.handle, info.did);
    Ok(())
}
