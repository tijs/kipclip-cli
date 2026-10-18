use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use miette::{Result, miette};

/// Resolve the config path without creating files or directories on a read.
/// `dirs` uses ~/Library/Application Support on macOS and XDG_CONFIG_HOME on Linux.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kipclip")
}

/// Path to the existing Jacquard OAuth store (format unchanged).
pub fn auth_store_path() -> PathBuf {
    config_dir().join("session.json")
}

/// Active session: cached OAuth identity, or a minimal app-password session.
pub fn session_info_path() -> PathBuf {
    config_dir().join("whoami.json")
}

fn store_error() -> miette::Report {
    // Never attach filesystem/serde errors: paths and data can contain secrets.
    miette!("KIP_STORE_FAILED: Could not securely access the local session store.")
}

/// Create/harden the leaf directory before placing any credentials in it.
/// Refuse symlink directories; never silently fall back to permissive storage.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path).map_err(|_| store_error())?;
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .map_err(|_| store_error())?;
        if dir.metadata().map_err(|_| store_error())?.uid() != unsafe { libc::geteuid() } {
            return Err(store_error());
        }
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|_| store_error())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(miette!(
            "KIP_STORE_FAILED: Private session storage requires Unix file permissions."
        ))
    }
}

/// Open a regular session file without following links (or blocking on a FIFO).
/// Harden legacy OAuth files in place, without changing their contents/format.
fn open_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

/// Bounded reads; caller decides whether NotFound means login is required.
pub fn read_private_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = open_private_file(path)?.take(128 * 1024 + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

/// Test convenience only. Production must retain the transaction for the entire
/// lifetime of Jacquard's store, not just its initialization.
#[cfg(test)]
pub fn prepare_oauth_store(path: &Path) -> Result<()> {
    SessionTransaction::acquire(path)?.prepare_oauth_store(path, true)
}

fn prepare_oauth_store_locked(path: &Path, create: bool) -> Result<()> {
    match open_private_file(path) {
        Ok(_) => Ok(()),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            // create_new never follows a symlink or truncates another session.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| store_error())?;
                file.write_all(b"{}").map_err(|_| store_error())?;
                file.sync_all().map_err(|_| store_error())?;
                Ok(())
            }
            #[cfg(not(unix))]
            Err(store_error())
        }
        Err(_) => Err(store_error()),
    }
}

/// Atomic replacement: private temp inode, fsync, rename, fsync directory.
/// Existing symlinks/hardlinks/non-regular files are refused, not followed.
/// No password is ever passed here, only validated session/identity material.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    SessionTransaction::acquire(path)?.write(path, data)
}

fn write_private_file_locked(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(store_error)?;
    ensure_private_dir(parent)?;
    match open_private_file(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(store_error()),
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|_| store_error())?;
    temp.write_all(data).map_err(|_| store_error())?;
    temp.as_file().sync_all().map_err(|_| store_error())?;
    temp.persist(path).map_err(|_| store_error())?;
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| store_error())?;
    Ok(())
}

/// One persistent inode per private user directory. Never unlink this lock,
/// including on logout: waiters must all lock the same inode. flock applies
/// across CLI processes (and independent opens in this process); the RwLock in
/// AppSession is not a replacement for this transaction.
pub struct SessionTransaction {
    _lock: std::fs::File,
    parent: PathBuf,
}

impl SessionTransaction {
    /// OAuth holds a transaction across async I/O and user interaction. Wait for
    /// another process off the executor; cancellation never starts store I/O.
    pub async fn acquire_async(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::acquire(&path))
            .await
            .map_err(|_| store_error())?
    }

    pub fn acquire(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            let parent = path.parent().ok_or_else(store_error)?;
            ensure_private_dir(parent)?;
            let lock_path = parent.join(".session.lock");
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&lock_path)
                .map_err(|_| store_error())?;
            let metadata = lock.metadata().map_err(|_| store_error())?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(store_error());
            }
            lock.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| store_error())?;
            loop {
                // SAFETY: the fd is owned by lock for this call's lifetime.
                if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return Err(store_error());
                }
            }
            // Refuse a lock path replaced while we waited rather than silently
            // entering a transaction on an obsolete/unlinked inode.
            let current = std::fs::symlink_metadata(&lock_path).map_err(|_| store_error())?;
            if !current.is_file()
                || current.nlink() != 1
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(store_error());
            }
            Ok(Self {
                _lock: lock,
                parent: parent.into(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(store_error())
        }
    }

    /// Harden/initialize the legacy OAuth map while ALREADY locked. Restore
    /// passes create=false so a stale cached identity cannot recreate logout.
    pub fn prepare_oauth_store(&self, path: &Path, create: bool) -> Result<()> {
        if path.parent() != Some(self.parent.as_path()) {
            return Err(store_error());
        }
        prepare_oauth_store_locked(path, create)
    }

    pub fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        if path.parent() != Some(self.parent.as_path()) {
            return Err(store_error());
        }
        write_private_file_locked(path, data)
    }

    fn remove(&self, name: &str) -> Result<()> {
        let path = self.parent.join(name);
        match open_private_file(&path) {
            Ok(_) => std::fs::remove_file(path).map_err(|_| store_error()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(store_error()),
        }
    }
}

/// Both removals are serialized with active-session activation/refresh. The
/// lock file intentionally remains, preventing split locks after logout.
pub fn clear_sessions(directory: &Path) -> Result<()> {
    // A logout of a never-initialized user should not create a directory.
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(store_error()),
        Ok(_) => {}
    }
    let transaction = SessionTransaction::acquire(&directory.join("whoami.json"))?;
    // Remove the active pointer first, so partial failures cannot resurrect it.
    transaction.remove("whoami.json")?;
    transaction.remove("session.json")?;
    std::fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| store_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn interprocess_lock_is_private_stable_and_survives_logout() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("store");
        let path = directory.join("whoami.json");
        write_private_file(&path, b"synthetic session").unwrap();
        let lock = directory.join(".session.lock");
        let inode = lock.metadata().unwrap().ino();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
        let guard = SessionTransaction::acquire(&path).unwrap();
        assert_eq!(lock.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(lock.metadata().unwrap().len(), 0);
        assert!(
            guard
                .write(&root.path().join("outside"), b"refused")
                .is_err()
        );
        drop(guard);
        clear_sessions(&directory).unwrap();
        assert!(!path.exists());
        assert_eq!(lock.metadata().unwrap().ino(), inode);
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn interprocess_lock_refuses_symlink_hardlink_fifo_and_directory() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        for kind in ["symlink", "hardlink", "fifo", "directory"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("store/whoami.json");
            ensure_private_dir(path.parent().unwrap()).unwrap();
            let lock = path.parent().unwrap().join(".session.lock");
            let target = root.path().join("target");
            std::fs::write(&target, b"unchanged").unwrap();
            match kind {
                "symlink" => symlink(&target, &lock).unwrap(),
                "hardlink" => std::fs::hard_link(&target, &lock).unwrap(),
                "directory" => std::fs::create_dir(&lock).unwrap(),
                "fifo" => {
                    let name = CString::new(lock.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            let error = SessionTransaction::acquire(&path).err().unwrap();
            assert!(error.to_string().contains("KIP_STORE_FAILED"));
            assert!(!format!("{error:?}").contains("target"));
            assert!(write_private_file(&path, b"refused").is_err());
            assert!(!path.exists());
            assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_replace_hardens_permissions_without_leaving_temps() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("store");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let file = dir.join("session.json");
        std::fs::write(&file, b"old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let inode = file.metadata().unwrap().ino();
        write_private_file(&file, b"session material").unwrap();
        assert_ne!(
            file.metadata().unwrap().ino(),
            inode,
            "must replace, not truncate"
        );
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(dir.metadata().unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read(&file).unwrap(), b"session material");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn private_store_refuses_links_and_non_regular_files() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        let link = root.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(write_private_file(&link, b"replacement").is_err());
        assert!(read_private_file(&link).is_err());
        assert!(prepare_oauth_store(&link).is_err());
        let hardlink = root.path().join("hardlink");
        std::fs::hard_link(&target, &hardlink).unwrap();
        assert!(write_private_file(&hardlink, b"replacement").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        let directory = root.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(write_private_file(&directory, b"replacement").is_err());
        let directory_link = root.path().join("directory-link");
        symlink(&directory, &directory_link).unwrap();
        assert!(write_private_file(&directory_link.join("session"), b"replacement").is_err());
        assert!(std::fs::read_dir(directory).unwrap().next().is_none());
    }

    #[test]
    fn legacy_oauth_store_is_preserved_and_created_privately() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("auth/session.json");
        prepare_oauth_store(&path).unwrap();
        assert_eq!(read_private_file(&path).unwrap(), b"{}");
        std::fs::write(&path, b"{\"existing\":\"oauth fixture\"}").unwrap();
        prepare_oauth_store(&path).unwrap();
        assert_eq!(
            read_private_file(&path).unwrap(),
            b"{\"existing\":\"oauth fixture\"}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
