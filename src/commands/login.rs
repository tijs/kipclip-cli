use miette::Result;

use crate::kipclip::auth;

pub async fn run(handle: &str, headless: bool) -> Result<()> {
    if headless {
        println!("Open the authorization URL below in a local browser.");
    } else {
        println!("Opening browser for AT Protocol login…");
    }
    let info = if headless {
        auth::login_headless(handle).await?
    } else {
        auth::login(handle).await?
    };
    println!("Logged in as {} ({})", info.handle, info.did);
    Ok(())
}
