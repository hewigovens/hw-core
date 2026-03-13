use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hw_wallet::ble::SessionBootstrapOptions;
use trezor_connect::thp::FileStorage;
use trezor_connect::thp::storage::ThpStorage;

use crate::errors::HWCoreError;
use crate::types::SessionRetryPolicy;

pub(crate) const DEFAULT_THP_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn bootstrap_options(
    try_to_unlock: bool,
    retry_policy: Option<SessionRetryPolicy>,
) -> SessionBootstrapOptions {
    SessionBootstrapOptions {
        thp_timeout: DEFAULT_THP_TIMEOUT,
        try_to_unlock,
        passphrase: None,
        on_device: false,
        derive_cardano: false,
        retry_policy: retry_policy.unwrap_or_default(),
    }
}

pub(crate) fn storage_from_path(storage_path: String) -> Result<Arc<dyn ThpStorage>, HWCoreError> {
    let trimmed = storage_path.trim();
    if trimmed.is_empty() {
        return Err(HWCoreError::Validation(
            "storage path must not be empty".to_string(),
        ));
    }
    Ok(Arc::new(FileStorage::new(PathBuf::from(trimmed))) as Arc<dyn ThpStorage>)
}
