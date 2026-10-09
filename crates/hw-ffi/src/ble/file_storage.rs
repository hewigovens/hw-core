use std::path::PathBuf;
use std::sync::Arc;

use trezor_connect::thp::FileStorage;
use trezor_connect::thp::storage::ThpStorage;

use crate::errors::HWCoreError;

pub(super) trait FileStorageExt {
    fn from_storage_path(storage_path: String) -> Result<Arc<dyn ThpStorage>, HWCoreError>;
}

impl FileStorageExt for FileStorage {
    fn from_storage_path(storage_path: String) -> Result<Arc<dyn ThpStorage>, HWCoreError> {
        let trimmed = storage_path.trim();
        if trimmed.is_empty() {
            return Err(HWCoreError::Validation(
                "storage path must not be empty".to_string(),
            ));
        }
        Ok(Arc::new(Self::new(PathBuf::from(trimmed))))
    }
}
