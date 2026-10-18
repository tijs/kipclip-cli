//! Keep Jacquard's *entire* store/client/session lifetime in one OS transaction.
//!
//! FileAuthStore does read/modify/write itself, including during restore and
//! implicit refresh. Per-method flock or an init-only lock cannot protect the
//! login token-write -> identity-activation gap, nor a refresh already in flight.
//! The registry owns this adapter through Arc: every surviving client/session or
//! store handle keeps the SAME transaction alive. No method reacquires flock.
//! The inner mutex also serializes Jacquard's non-atomic writes within a process.

use std::path::{Path, PathBuf};

use jacquard::IntoStatic;
use jacquard::client::FileAuthStore;
use jacquard::oauth::authstore::ClientAuthStore;
use jacquard::oauth::session::{AuthRequestData, ClientSessionData};
use jacquard::session::SessionStoreError;
use jacquard::types::string::Did;
use miette::{Result, miette};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::{AuthMethod, SessionInfo, config, parse_session_info};

pub struct OAuthStore {
    inner: Mutex<FileAuthStore>,
    transaction: config::SessionTransaction,
    identity_path: PathBuf,
}

impl OAuthStore {
    /// Only a NEW explicit OAuth login may initialize a missing token store.
    pub(super) async fn login_at(path: &Path) -> Result<Self> {
        let transaction = config::SessionTransaction::acquire_async(path).await?;
        Self::open(path, transaction, true)
    }

    pub(super) async fn restore_at(path: &Path, expected: &SessionInfo) -> Result<Self> {
        let transaction = config::SessionTransaction::acquire_async(path).await?;
        let identity_path = path.with_file_name("whoami.json");
        let bytes = Zeroizing::new(config::read_private_file(&identity_path).map_err(|_| {
            miette!("KIP_RESTORE_FAILED: The saved OAuth identity is no longer active.")
        })?);
        let current = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|data| parse_session_info(data).ok());
        if expected.auth_method != AuthMethod::OAuth || current.as_ref() != Some(expected) {
            return Err(miette!(
                "KIP_RESTORE_FAILED: The saved OAuth identity is no longer active."
            ));
        }
        // Do NOT call an initializing constructor until both files have been
        // checked under the lock. A restore queued behind logout must not leave
        // even an empty orphan session.json, much less rewrite cached tokens.
        Self::open(path, transaction, false)
    }

    fn open(path: &Path, transaction: config::SessionTransaction, create: bool) -> Result<Self> {
        transaction.prepare_oauth_store(path, create)?;
        Ok(Self {
            inner: Mutex::new(FileAuthStore::new(path)),
            transaction,
            identity_path: path.with_file_name("whoami.json"),
        })
    }

    pub(super) fn activate(&self, info: &SessionInfo) -> Result<()> {
        let json = serde_json::to_vec_pretty(info).map_err(|_| {
            miette!("KIP_STORE_FAILED: Could not encode the local session identity.")
        })?;
        // The store owns the already-held transaction. Using write_private_file
        // here would independently open/flock the inode and deadlock ourselves.
        self.transaction.write(&self.identity_path, &json)
    }
}

impl ClientAuthStore for OAuthStore {
    async fn get_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> std::result::Result<Option<ClientSessionData<'_>>, SessionStoreError> {
        self.inner
            .lock()
            .await
            .get_session(did, session_id)
            .await
            .map(|data| data.map(IntoStatic::into_static))
    }

    async fn upsert_session(
        &self,
        session: ClientSessionData<'_>,
    ) -> std::result::Result<(), SessionStoreError> {
        self.inner.lock().await.upsert_session(session).await
    }

    async fn delete_session(
        &self,
        did: &Did<'_>,
        session_id: &str,
    ) -> std::result::Result<(), SessionStoreError> {
        self.inner
            .lock()
            .await
            .delete_session(did, session_id)
            .await
    }

    async fn get_auth_req_info(
        &self,
        state: &str,
    ) -> std::result::Result<Option<AuthRequestData<'_>>, SessionStoreError> {
        self.inner
            .lock()
            .await
            .get_auth_req_info(state)
            .await
            .map(|data| data.map(IntoStatic::into_static))
    }

    async fn save_auth_req_info(
        &self,
        info: &AuthRequestData<'_>,
    ) -> std::result::Result<(), SessionStoreError> {
        self.inner.lock().await.save_auth_req_info(info).await
    }

    async fn delete_auth_req_info(
        &self,
        state: &str,
    ) -> std::result::Result<(), SessionStoreError> {
        self.inner.lock().await.delete_auth_req_info(state).await
    }
}
