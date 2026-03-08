use std::io::Write;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};

/// Returns the kipclip config directory (~/.config/kipclip/)
/// Created with 0700 permissions on Unix to protect credentials.
pub fn config_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kipclip");
    std::fs::create_dir_all(&dir).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    }
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

/// Write a file with 0600 permissions atomically (no TOCTOU race).
/// On non-Unix, falls back to std::fs::write.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .into_diagnostic()?;
        file.write_all(data).into_diagnostic()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).into_diagnostic()?;
    }
    Ok(())
}
