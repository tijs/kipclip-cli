use miette::Result;

use crate::kipclip::auth;

pub fn run() -> Result<()> {
    auth::logout()?;
    println!("Logged out.");
    Ok(())
}
