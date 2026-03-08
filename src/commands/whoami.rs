use miette::Result;

use crate::kipclip::auth;

pub fn run(json: bool) -> Result<()> {
    let info = auth::get_session_info()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&info).unwrap_or_default()
        );
    } else {
        println!("Handle: {}", info.handle);
        println!("DID:    {}", info.did);
    }
    Ok(())
}
