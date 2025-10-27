use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::types::KnownCredential;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub static_key: Option<Vec<u8>>,
    pub known_credentials: Vec<KnownCredential>,
}

#[async_trait]
pub trait ThpStorage: Send + Sync {
    async fn load(&self) -> Result<HostSnapshot, StorageError>;
    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError>;
}

pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn atomic_write(path: &PathBuf, data: &[u8]) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut tmp = path.clone();
        tmp.set_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[async_trait]
impl ThpStorage for FileStorage {
    async fn load(&self) -> Result<HostSnapshot, StorageError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                if bytes.is_empty() {
                    Ok(HostSnapshot::default())
                } else {
                    Ok(serde_json::from_slice(&bytes)?)
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HostSnapshot::default()),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError> {
        let data = serde_json::to_vec_pretty(snapshot)?;
        Self::atomic_write(&self.path, &data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn roundtrip_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("thp.json");
        let storage = FileStorage::new(&path);

        let snapshot = HostSnapshot {
            static_key: Some(vec![1, 2, 3]),
            known_credentials: vec![KnownCredential {
                credential: "cred".into(),
                trezor_static_public_key: Some(vec![4; 32]),
                autoconnect: true,
            }],
        };

        storage.persist(&snapshot).await.unwrap();
        let loaded = storage.load().await.unwrap();
        assert_eq!(loaded.static_key, snapshot.static_key);
        assert_eq!(loaded.known_credentials.len(), 1);
        assert_eq!(
            loaded.known_credentials[0].trezor_static_public_key,
            snapshot.known_credentials[0].trezor_static_public_key
        );
    }

    #[tokio::test]
    async fn load_missing_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let storage = FileStorage::new(&path);

        let loaded = storage.load().await.unwrap();
        assert!(loaded.static_key.is_none());
        assert!(loaded.known_credentials.is_empty());
    }
}
