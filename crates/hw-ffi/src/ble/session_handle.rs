use std::sync::Arc;

use ble_transport::BleSession;
use hw_wallet::ble::SessionBootstrapOptions;
use tokio::sync::Mutex as AsyncMutex;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{FileStorage, ThpWorkflow};

use super::BleWorkflowHandle;
use super::file_storage::FileStorageExt;
use crate::errors::HWCoreError;
use crate::types::HostConfig;

#[derive(uniffi::Object)]
pub struct BleSessionHandle {
    session: AsyncMutex<Option<BleSession>>,
}

impl BleSessionHandle {
    pub(super) fn new(session: BleSession) -> Self {
        Self {
            session: AsyncMutex::new(Some(session)),
        }
    }

    async fn take_session(&self) -> Result<BleSession, HWCoreError> {
        let mut guard = self.session.lock().await;
        guard
            .take()
            .ok_or_else(|| HWCoreError::Unknown("BLE session already consumed".to_string()))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl BleSessionHandle {
    #[uniffi::method]
    pub async fn into_workflow_with_storage(
        self: Arc<Self>,
        config: HostConfig,
        storage_path: Option<String>,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let session = self.take_session().await?;
        let thp_timeout = SessionBootstrapOptions::default().thp_timeout;
        let backend = BleBackend::from_session(session, thp_timeout);
        let workflow = if let Some(path) = storage_path {
            let storage = FileStorage::from_storage_path(path)?;
            ThpWorkflow::with_storage(backend, config.into(), storage).await?
        } else {
            ThpWorkflow::new(backend, config.into())
        };
        Ok(Arc::new(BleWorkflowHandle::new(workflow)))
    }
}
