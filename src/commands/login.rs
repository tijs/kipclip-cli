use miette::Result;

use crate::kipclip::{app_session, auth};

pub async fn run(handle: &str, headless: bool, app_password_env: Option<&str>) -> Result<()> {
    if let Some(env_name) = app_password_env {
        // Nothing is printed before validation; only this explicit arm reads an
        // environment variable. Never spawn a vault command or prompt for it.
        let info = app_session::login_env(handle, env_name).await?;
        println!("Logged in as {} ({})", info.handle, info.did);
        return Ok(());
    }
    if headless {
        println!("Open the authorization URL below in a browser, then paste the callback URL.");
    } else {
        println!("Opening browser for AT Protocol login; then paste the callback URL…");
    }
    let info = auth::login(handle, headless).await?;
    println!("Logged in as {} ({})", info.handle, info.did);
    Ok(())
}
