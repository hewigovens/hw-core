use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs, io};

use anyhow::{Context, Result};
use async_trait::async_trait;
use keyring::{Entry, Error as KeyringError};
use tokio::task;
use trezor_connect::thp::{FileStorage, HostSnapshot, StorageError, ThpStorage};

const KEYCHAIN_SERVICE: &str = "hw-core";
const KEYCHAIN_ACCOUNT: &str = "thp-host";

/// Where the CLI keeps the host pairing snapshot, which holds the THP static private key.
pub enum HostStore {
    Keychain(Arc<KeychainStorage>),
    File(PathBuf),
}

impl HostStore {
    /// Uses `explicit_path` when given. Otherwise prefers the OS credential store, moving an
    /// existing default file into it, and warns before falling back to that plaintext file.
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

    /// Removes the saved pairing state, returning whether there was any.
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
            Self::Keychain(_) => write!(f, "OS credential store ({KEYCHAIN_SERVICE})"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Keeps the snapshot in the macOS Keychain, Windows Credential Manager or Secret Service.
pub struct KeychainStorage {
    entry: Arc<Entry>,
    default_file: PathBuf,
}

impl KeychainStorage {
    async fn open(default_file: PathBuf) -> Result<Self, StorageError> {
        let entry = task::spawn_blocking(|| Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT))
            .await
            .map_err(backend_error)?
            .map_err(backend_error)?;
        let storage = Self {
            entry: Arc::new(entry),
            default_file,
        };
        // Creating an entry does not touch the store, so prove it is reachable and unlocked.
        storage.read().await?;
        Ok(storage)
    }

    /// Keychain calls block, and the Secret Service client must not run on a runtime thread.
    async fn with_entry<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Entry) -> Result<T, KeyringError> + Send + 'static,
    ) -> Result<T, StorageError> {
        let entry = self.entry.clone();
        task::spawn_blocking(move || op(&entry))
            .await
            .map_err(backend_error)?
            .map_err(backend_error)
    }

    async fn read(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.with_entry(|entry| match entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(err) => Err(err),
        })
        .await
    }

    async fn import_default_file(&self) -> Result<()> {
        if !self.default_file.exists() {
            return Ok(());
        }
        let path = self.default_file.display();
        if self.read().await?.is_some() {
            eprintln!(
                "warning: ignoring plaintext pairing file {path} because the OS credential store \
                 already has pairing state; delete the file or run `pair --force`"
            );
            return Ok(());
        }
        let snapshot = FileStorage::new(&self.default_file)
            .load()
            .await
            .with_context(|| format!("failed to read pairing state from {path}"))?;
        self.persist(&snapshot)
            .await
            .context("failed to move pairing state to the OS credential store")?;
        fs::remove_file(&self.default_file)
            .with_context(|| format!("failed to remove plaintext pairing state at {path}"))?;
        println!("Moved pairing state from {path} to the OS credential store.");
        Ok(())
    }

    async fn clear(&self) -> Result<bool> {
        let removed_entry = self
            .with_entry(|entry| match entry.delete_credential() {
                Ok(()) => Ok(true),
                Err(KeyringError::NoEntry) => Ok(false),
                Err(err) => Err(err),
            })
            .await?;
        Ok(remove_if_present(&self.default_file)? || removed_entry)
    }
}

#[async_trait]
impl ThpStorage for KeychainStorage {
    async fn load(&self) -> Result<HostSnapshot, StorageError> {
        match self.read().await? {
            Some(bytes) => HostSnapshot::from_json(&bytes),
            None => Ok(HostSnapshot::default()),
        }
    }

    async fn persist(&self, snapshot: &HostSnapshot) -> Result<(), StorageError> {
        let bytes = snapshot.to_json()?;
        self.with_entry(move |entry| entry.set_secret(&bytes)).await
    }
}

fn backend_error(error: impl fmt::Display) -> StorageError {
    StorageError::Backend(error.to_string())
}

fn remove_if_present(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to clear pairing state at {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    fn mock_keychain(account: &str, default_file: PathBuf) -> KeychainStorage {
        static STORE: Once = Once::new();
        STORE.call_once(|| {
            keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap())
        });
        KeychainStorage {
            entry: Arc::new(Entry {
                inner: keyring_core::Entry::new(KEYCHAIN_SERVICE, account).unwrap(),
            }),
            default_file,
        }
    }

    fn snapshot(static_key: u8) -> HostSnapshot {
        HostSnapshot {
            static_key: Some(vec![static_key; 32]),
            ..HostSnapshot::default()
        }
    }

    async fn write_file(path: &Path, static_key: u8) {
        FileStorage::new(path)
            .persist(&snapshot(static_key))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn default_file_moves_into_keychain_and_clear_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("thp-host.json");
        write_file(&path, 7).await;
        let keychain = mock_keychain("import", path.clone());

        keychain.import_default_file().await.unwrap();

        assert!(!path.exists());
        assert_eq!(keychain.load().await.unwrap().static_key, Some(vec![7; 32]));
        assert!(keychain.clear().await.unwrap());
        assert!(!keychain.clear().await.unwrap());
        assert_eq!(keychain.load().await.unwrap().static_key, None);
    }

    #[tokio::test]
    async fn existing_keychain_state_wins_over_default_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("thp-host.json");
        write_file(&path, 7).await;
        let keychain = mock_keychain("existing", path.clone());
        keychain.persist(&snapshot(9)).await.unwrap();

        keychain.import_default_file().await.unwrap();

        assert!(path.exists());
        assert_eq!(keychain.load().await.unwrap().static_key, Some(vec![9; 32]));
    }

    #[tokio::test]
    async fn unreadable_default_file_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("thp-host.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();
        let keychain = mock_keychain("corrupt", path.clone());

        assert!(keychain.import_default_file().await.is_err());
        assert!(path.exists());
    }
}
