use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::types::KnownCredential;

#[cfg(target_vendor = "apple")]
#[path = "apple_acl.rs"]
mod acl;
#[cfg(all(unix, not(target_vendor = "apple")))]
#[path = "no_acl.rs"]
mod acl;
#[cfg(unix)]
mod unix;
#[cfg(not(unix))]
mod unsupported;

#[cfg(unix)]
use self::unix as platform;
#[cfg(not(unix))]
use unsupported as platform;

#[cfg(all(test, target_vendor = "apple"))]
mod apple_tests;
#[cfg(all(test, unix))]
mod tests;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("storage snapshot schema version {found} does not match supported version {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
}

pub const CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub schema_version: u32,
    pub static_key: Option<Vec<u8>>,
    pub known_credentials: Vec<KnownCredential>,
}

impl Default for HostSnapshot {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION,
            static_key: None,
            known_credentials: Vec::new(),
        }
    }
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
}

#[async_trait]
impl ThpStorage for FileStorage {
    async fn load(&self) -> Result<HostSnapshot, StorageError> {
        match platform::read_secure_file(&self.path)? {
            Some(bytes) if bytes.is_empty() => Ok(HostSnapshot::default()),
            Some(bytes) => {
                let snapshot: HostSnapshot = serde_json::from_slice(&bytes)?;
                if snapshot.schema_version != CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION {
                    Err(StorageError::UnsupportedSchemaVersion {
                        found: snapshot.schema_version,
                        supported: CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION,
                    })
                } else {
                    Ok(snapshot)
                }
            }
            None => Ok(HostSnapshot::default()),
        }
    }

    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError> {
        let data = serde_json::to_vec_pretty(snapshot)?;
        platform::atomic_write(&self.path, &data)?;
        Ok(())
    }
}
