use std::path::PathBuf;

use async_trait::async_trait;

use super::platform;
use super::{HostSnapshot, StorageError, ThpStorage};

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
            Some(bytes) => HostSnapshot::from_json(&bytes),
            None => Ok(HostSnapshot::default()),
        }
    }

    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError> {
        let data = serde_json::to_vec_pretty(snapshot)?;
        platform::atomic_write(&self.path, &data)?;
        Ok(())
    }
}
