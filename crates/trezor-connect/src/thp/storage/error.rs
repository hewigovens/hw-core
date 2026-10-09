use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("storage snapshot schema version {found} does not match supported version {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
}
