use std::path::PathBuf;

/// Returns the kipclip config directory (~/.config/kipclip/)
pub fn config_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kipclip");
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Path to the OAuth session store file
pub fn auth_store_path() -> String {
    config_dir()
        .join("session.json")
        .to_string_lossy()
        .into_owned()
}

/// Path to the cached session info (DID, handle)
pub fn session_info_path() -> PathBuf {
    config_dir().join("whoami.json")
}

/// Appview base URL
pub fn appview_url() -> String {
    std::env::var("KIPCLIP_APPVIEW_URL").unwrap_or_else(|_| "https://kipclip.com".to_string())
}
