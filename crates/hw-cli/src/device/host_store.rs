use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs, io};

use anyhow::{Context, Result};
use trezor_connect::thp::{FileStorage, ThpStorage};

use super::keychain_storage::KeychainStorage;

/// Where the CLI keeps the host pairing snapshot, which holds the THP static private key.
pub enum HostStore {
    Keychain(Arc<KeychainStorage>),
    File(PathBuf),
}

impl HostStore {
    /// Prefers the OS credential store unless `explicit_path` selects a file.
    pub async fn resolve(explicit_path: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit_path {
            return Ok(Self::File(path.to_path_buf()));
        }
        let default_path = Self::default_path();
        match KeychainStorage::open(default_path.clone()).await {
            Ok(keychain) => {
                keychain.import_default_file().await?;
                Ok(Self::Keychain(Arc::new(keychain)))
            }
            Err(err) => {
                eprintln!(
                    "warning: OS credential store unavailable ({err}); pairing secrets will be \
                     stored unencrypted in {}",
                    default_path.display()
                );
                Ok(Self::File(default_path))
            }
        }
    }

    fn default_path() -> PathBuf {
        env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".hw-core")
            .join("thp-host.json")
    }

    pub fn thp_storage(&self) -> Arc<dyn ThpStorage> {
        match self {
            Self::Keychain(keychain) => keychain.clone(),
            Self::File(path) => Arc::new(FileStorage::new(path)),
        }
    }

    pub async fn clear(&self) -> Result<bool> {
        match self {
            Self::Keychain(keychain) => keychain.clear().await,
            Self::File(path) => remove_if_present(path),
        }
    }
}

impl fmt::Display for HostStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keychain(_) => f.write_str("OS credential store"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

pub(super) fn remove_if_present(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to clear pairing state at {}", path.display()))
        }
    }
}
