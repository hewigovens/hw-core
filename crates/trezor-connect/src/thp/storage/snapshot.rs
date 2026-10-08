use serde::{Deserialize, Serialize};

use super::StorageError;
use crate::thp::types::{HostConfig, KnownCredential};

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

impl HostSnapshot {
    /// Parses a stored snapshot; empty input is a fresh host.
    pub fn from_json(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let snapshot: Self = serde_json::from_slice(bytes)?;
        if snapshot.schema_version != CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion {
                found: snapshot.schema_version,
                supported: CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION,
            });
        }
        Ok(snapshot)
    }

    /// Overrides `config` with the persisted host key and credentials, when present.
    pub fn restore(self, config: &mut HostConfig) {
        if let Some(static_key) = self.static_key {
            config.static_key = Some(static_key);
        }
        if !self.known_credentials.is_empty() {
            config.known_credentials = self.known_credentials;
        }
    }
}

impl From<&HostConfig> for HostSnapshot {
    fn from(config: &HostConfig) -> Self {
        Self {
            static_key: config.static_key.clone(),
            known_credentials: config.known_credentials.clone(),
            ..Self::default()
        }
    }
}
