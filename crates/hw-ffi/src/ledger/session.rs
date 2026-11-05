use super::LedgerAppInfo;
use crate::HWCoreError;
use hw_wallet::ledger::{LedgerTypedDataExt, LedgerWalletExt};
use ledger_connect::{LedgerBleTransport, LedgerClient};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard, watch};

#[derive(uniffi::Object)]
pub struct LedgerSessionHandle {
    client: Mutex<Option<LedgerClient<LedgerBleTransport>>>,
    cancellation: watch::Sender<bool>,
}

impl LedgerSessionHandle {
    pub(crate) fn new(client: LedgerClient<LedgerBleTransport>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
            cancellation: watch::channel(false).0,
        }
    }
    fn client(
        &self,
    ) -> Result<MappedMutexGuard<'_, LedgerClient<LedgerBleTransport>>, HWCoreError> {
        let slot = self
            .client
            .try_lock()
            .map_err(|_| HWCoreError::DeviceBusy("Ledger operation in progress".into()))?;
        MutexGuard::try_map(slot, Option::as_mut)
            .map_err(|_| HWCoreError::Disconnected("Ledger session closed".into()))
    }
    async fn with_client<T>(
        &self,
        operation: impl AsyncFnOnce(&mut LedgerClient<LedgerBleTransport>) -> Result<T, HWCoreError>,
    ) -> Result<T, HWCoreError> {
        // Subscribe before acquiring the client so close/cancel cannot be missed.
        let mut cancellation = self.cancellation.subscribe();
        if *cancellation.borrow() {
            return Err(HWCoreError::Disconnected("Ledger session closed".into()));
        }
        let mut client = self.client()?;
        tokio::select! {
            biased;
            _ = cancellation.changed() => Err(HWCoreError::ActionCancelled("Ledger request cancelled; reject any remaining device prompt and reconnect".into())),
            result = operation(&mut client) => result,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerSessionHandle {
    /// Whether the idle session can accept another request. Busy sessions return false.
    pub fn is_ready(&self) -> bool {
        !*self.cancellation.borrow()
            && self
                .client
                .try_lock()
                .is_ok_and(|slot| slot.as_ref().is_some_and(LedgerClient::is_ready))
    }

    pub async fn app_info(&self) -> Result<LedgerAppInfo, HWCoreError> {
        self.with_client(async |client| Ok(client.app_info().await?))
            .await
    }

    pub async fn session_state(&self) -> Result<crate::SessionState, HWCoreError> {
        self.with_client(async |client| {
            client.app_info().await?;
            Ok(crate::SessionState::new(crate::SessionPhase::Ready, None))
        })
        .await
    }

    pub fn cancel(&self) {
        // Host cancellation retires this session, including requests not polled yet.
        self.cancellation.send_replace(true);
    }

    pub async fn get_address(
        &self,
        request: crate::GetAddressRequest,
    ) -> Result<crate::AddressResult, HWCoreError> {
        let raw = request.try_into()?;
        self.with_client(async |client| Ok(client.get_address(&raw).await?.into()))
            .await
    }

    pub async fn sign_tx(
        &self,
        request: crate::SignTxRequest,
    ) -> Result<crate::SignTxResult, HWCoreError> {
        // The shared Solana request has no chunkify field; reject before conversion drops it.
        if request.chunkify {
            return Err(HWCoreError::Unsupported(
                "Ledger does not support chunkify".into(),
            ));
        }
        let raw = request.try_into()?;
        self.with_client(async |client| {
            Ok(crate::SignTxResult::new(&raw, client.sign_tx(&raw).await?))
        })
        .await
    }

    pub async fn sign_message(
        &self,
        request: crate::SignMessageRequest,
    ) -> Result<crate::SignMessageResult, HWCoreError> {
        let raw = request.try_into()?;
        self.with_client(async |client| Ok(client.sign_message(&raw).await?.into()))
            .await
    }

    pub async fn sign_bitcoin_tx(
        &self,
        request: crate::BitcoinSignTxRequest,
    ) -> Result<crate::SignTxResult, HWCoreError> {
        let raw = trezor_connect::thp::SignTxRequest::Bitcoin(request.try_into()?);
        self.with_client(async |client| {
            Ok(crate::SignTxResult::new(&raw, client.sign_tx(&raw).await?))
        })
        .await
    }

    pub async fn sign_typed_data(
        &self,
        request: crate::SignTypedDataRequest,
    ) -> Result<crate::SignTypedDataResult, HWCoreError> {
        let raw = request.try_into()?;
        self.with_client(async |client| client.sign_verified_typed_data(&raw).await?.try_into())
            .await
    }

    pub async fn disconnect(&self) -> Result<(), HWCoreError> {
        self.cancel();
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.take() {
            client.into_transport().disconnect().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_closes_admission_before_waiting_for_an_active_request() {
        let handle = std::sync::Arc::new(LedgerSessionHandle {
            client: Mutex::new(None),
            cancellation: watch::channel(false).0,
        });
        let guard = handle.client.lock().await;
        let mut closed = handle.cancellation.subscribe();
        let closing = handle.clone();
        let disconnect = tokio::spawn(async move { closing.disconnect().await });
        closed.changed().await.unwrap();
        assert!(matches!(
            handle.app_info().await,
            Err(HWCoreError::Disconnected(_))
        ));
        drop(guard);
        disconnect.await.unwrap().unwrap();
        assert!(matches!(
            handle.app_info().await,
            Err(HWCoreError::Disconnected(_))
        ));
    }

    #[tokio::test]
    async fn busy_and_closed_sessions_return_distinct_errors_without_queueing() {
        let handle = LedgerSessionHandle {
            client: Mutex::new(None),
            cancellation: watch::channel(false).0,
        };
        let guard = handle.client.lock().await;
        assert!(matches!(
            handle.app_info().await,
            Err(HWCoreError::DeviceBusy(_))
        ));
        drop(guard);
        assert!(matches!(
            handle.app_info().await,
            Err(HWCoreError::Disconnected(_))
        ));
        handle.disconnect().await.unwrap();
    }
}
