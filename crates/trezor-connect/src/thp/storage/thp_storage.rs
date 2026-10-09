use async_trait::async_trait;

use super::{HostSnapshot, StorageError};

#[async_trait]
pub trait ThpStorage: Send + Sync {
    async fn load(&self) -> Result<HostSnapshot, StorageError>;
    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError>;
}
