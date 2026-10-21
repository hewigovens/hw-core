use std::sync::Arc;

use async_trait::async_trait;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::{HostSnapshot, StorageError};

/// App-provided store for the host pairing snapshot, e.g. the Keychain or Android Keystore.
///
/// The snapshot is an opaque blob holding this host's THP static private key and the pairing
/// credentials the device issued to it. Whoever holds it can connect to the paired Trezor as this
/// host without pairing again (requests still need on-device confirmation), so keep it in secure
/// storage and never log it.
#[uniffi::export(with_foreign)]
pub trait HostStorage: Send + Sync {
    /// Returns the last persisted snapshot, or `None` before the first pairing.
    fn load(&self) -> Result<Option<Vec<u8>>, HostStorageError>;
    /// Replaces the stored snapshot; called after pairing and whenever credentials change.
    fn persist(&self, snapshot: Vec<u8>) -> Result<(), HostStorageError>;
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum HostStorageError {
    // Not `message`: Kotlin exceptions would clash with `Throwable.message`.
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HostStorageError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            reason: error.reason,
        }
    }
}

/// Adapts an app [`HostStorage`] to the workflow's [`ThpStorage`].
pub(super) struct ForeignStorage(Arc<dyn HostStorage>);

impl ForeignStorage {
    pub(super) fn shared(storage: Arc<dyn HostStorage>) -> Arc<dyn ThpStorage> {
        Arc::new(Self(storage))
    }
}

#[async_trait]
impl ThpStorage for ForeignStorage {
    async fn load(&self) -> Result<HostSnapshot, StorageError> {
        match self.0.load()? {
            Some(bytes) => HostSnapshot::from_json(&bytes),
            None => Ok(HostSnapshot::default()),
        }
    }

    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError> {
        Ok(self.0.persist(snapshot.to_json()?)?)
    }
}

impl From<HostStorageError> for StorageError {
    fn from(error: HostStorageError) -> Self {
        Self::Backend(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;
    use trezor_connect::thp::types::KnownCredential;

    use super::*;

    #[derive(Default)]
    struct MemoryHostStorage {
        blob: Mutex<Option<Vec<u8>>>,
        fail: bool,
    }

    impl HostStorage for MemoryHostStorage {
        fn load(&self) -> Result<Option<Vec<u8>>, HostStorageError> {
            Ok(self.blob.lock().clone())
        }

        fn persist(&self, snapshot: Vec<u8>) -> Result<(), HostStorageError> {
            if self.fail {
                return Err(HostStorageError::Failed {
                    reason: "keychain locked".into(),
                });
            }
            *self.blob.lock() = Some(snapshot);
            Ok(())
        }
    }

    #[tokio::test]
    async fn snapshot_roundtrips_through_app_storage_and_failures_surface() {
        let app = Arc::new(MemoryHostStorage::default());
        let storage = ForeignStorage(app.clone());
        assert!(storage.load().await.unwrap().static_key.is_none());

        let snapshot = HostSnapshot {
            static_key: Some(vec![7; 32]),
            known_credentials: vec![KnownCredential {
                credential: "cred".into(),
                trezor_static_public_key: Some(vec![9; 32]),
                autoconnect: false,
            }],
            ..HostSnapshot::default()
        };
        storage.persist(&snapshot).await.unwrap();
        let loaded = storage.load().await.unwrap();
        assert_eq!(loaded.static_key, Some(vec![7; 32]));
        assert_eq!(loaded.known_credentials[0].credential, "cred");

        let failing = ForeignStorage(Arc::new(MemoryHostStorage {
            fail: true,
            ..MemoryHostStorage::default()
        }));
        let err = failing.persist(&snapshot).await.unwrap_err();
        assert!(matches!(err, StorageError::Backend(ref message) if message == "keychain locked"));
    }
}
