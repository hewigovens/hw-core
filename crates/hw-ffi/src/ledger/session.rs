use super::{LedgerAppInfo, LedgerEthereumAddress, LedgerEthereumSignature, LedgerSigningResult};
use crate::HWCoreError;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ledger::{LedgerEthereumExt, LedgerSolanaExt, LedgerTypedDataExt};
use ledger_connect::{LedgerBleTransport, LedgerClient};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard, watch};

#[derive(uniffi::Object)]
pub struct LedgerSessionHandle {
    client: Mutex<Option<LedgerClient<LedgerBleTransport>>>,
    cancellation: watch::Sender<u64>,
}

impl LedgerSessionHandle {
    pub(crate) fn new(client: LedgerClient<LedgerBleTransport>) -> Self {
        Self {
            client: Mutex::new(Some(client)),
            cancellation: watch::channel(0).0,
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
        let mut client = self.client()?;
        let mut cancellation = self.cancellation.subscribe();
        tokio::select! {
            biased;
            _ = cancellation.changed() => Err(HWCoreError::ActionCancelled("Ledger request cancelled; reject any remaining device prompt and reconnect".into())),
            result = operation(&mut client) => result,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerSessionHandle {
    pub async fn app_info(&self) -> Result<LedgerAppInfo, HWCoreError> {
        self.with_client(async |client| Ok(client.app_info().await?))
            .await
    }

    pub async fn ethereum_address(
        &self,
        path: String,
        display: bool,
        chain_id: u64,
    ) -> Result<LedgerEthereumAddress, HWCoreError> {
        let path = parse_bip32_path(&path)?;
        self.with_client(async |client| {
            Ok(client.ethereum_address(&path, display, chain_id).await?)
        })
        .await
    }

    pub async fn sign_personal_message(
        &self,
        path: String,
        message: Vec<u8>,
    ) -> Result<LedgerSigningResult, HWCoreError> {
        let path = parse_bip32_path(&path)?;
        self.with_client(async |client| Ok(client.sign_verified_message(&path, &message).await?))
            .await
    }

    pub async fn sign_transaction(
        &self,
        path: String,
        transaction: Vec<u8>,
    ) -> Result<LedgerEthereumSignature, HWCoreError> {
        let path = parse_bip32_path(&path)?;
        self.with_client(async |client| Ok(client.sign_transaction(&path, &transaction).await?))
            .await
    }

    pub async fn sign_eip1559(
        &self,
        request: crate::SignTxRequest,
    ) -> Result<LedgerSigningResult, HWCoreError> {
        if request.chain != crate::Chain::Ethereum {
            return Err(HWCoreError::Validation(
                "Ledger EIP-1559 signing requires Ethereum".into(),
            ));
        }
        let raw: trezor_connect::thp::SignTxRequest = request.try_into()?;
        let trezor_connect::thp::SignTxRequest::Ethereum(tx) = raw else {
            return Err(HWCoreError::Validation("expected Ethereum request".into()));
        };
        self.with_client(async |client| Ok(client.sign_eip1559(&tx).await?))
            .await
    }

    pub fn cancel(&self) {
        self.cancellation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    pub async fn get_address(
        &self,
        request: crate::GetAddressRequest,
    ) -> Result<crate::AddressResult, HWCoreError> {
        if request.chain == crate::Chain::Bitcoin
            || request.chunkify
            || request.encoded_network.is_some()
        {
            return Err(HWCoreError::Unsupported(
                "Ledger supports Ethereum and Solana addresses without Trezor display options"
                    .into(),
            ));
        }
        if request.chain == crate::Chain::Solana {
            let path = parse_bip32_path(&request.path)?;
            let key = self
                .with_client(async |client| {
                    Ok(client
                        .solana_public_key(&path, request.show_on_device)
                        .await?)
                })
                .await?;
            let address = bs58::encode(key).into_string();
            return Ok(crate::AddressResult {
                chain: crate::Chain::Solana,
                public_key: request.include_public_key.then(|| address.clone()),
                address,
                mac: None,
            });
        }
        let address = self
            .ethereum_address(request.path, request.show_on_device, 1)
            .await?;
        Ok(crate::AddressResult {
            chain: crate::Chain::Ethereum,
            address: address.address,
            mac: None,
            public_key: request
                .include_public_key
                .then(|| format!("0x{}", hex::encode(address.public_key))),
        })
    }

    pub async fn sign_tx(
        &self,
        request: crate::SignTxRequest,
    ) -> Result<crate::SignTxResult, HWCoreError> {
        if request.chain == crate::Chain::Solana {
            if request.chunkify {
                return Err(HWCoreError::Unsupported(
                    "Ledger does not support chunkify".into(),
                ));
            }
            let raw: trezor_connect::thp::SignTxRequest = request.try_into()?;
            let trezor_connect::thp::SignTxRequest::Solana(tx) = &raw else {
                return Err(HWCoreError::Validation(
                    "expected Solana transaction".into(),
                ));
            };
            let signature = self
                .with_client(async |client| Ok(client.sign_verified_solana_transaction(tx).await?))
                .await?;
            return Ok(crate::SignTxResult::new(
                &raw,
                trezor_connect::thp::SignTxResponse::Solana { signature },
            ));
        }
        let result = self.sign_eip1559(request).await?;
        Ok(crate::SignTxResult {
            chain: crate::Chain::Ethereum,
            v: u32::from(result.v),
            r: result.r,
            s: result.s,
            signatures: vec![],
            // Match the shared result contract: this is the unsigned signing hash.
            tx_hash: Some(result.signing_hash),
            recovered_address: Some(result.recovered_address),
        })
    }

    pub async fn sign_message(
        &self,
        request: crate::SignMessageRequest,
    ) -> Result<crate::SignMessageResult, HWCoreError> {
        if request.chain == crate::Chain::Bitcoin
            || request.chunkify
            || request.encoded_network.is_some()
            || (request.chain != crate::Chain::Solana && !request.signers.is_empty())
        {
            return Err(HWCoreError::Unsupported(
                "Ledger supports Ethereum and Solana messages without Trezor display options"
                    .into(),
            ));
        }
        if request.chain == crate::Chain::Solana {
            let raw: trezor_connect::thp::SignMessageRequest = request.try_into()?;
            return self
                .with_client(async |client| {
                    Ok(client.sign_verified_solana_message(&raw).await?.into())
                })
                .await;
        }
        let message = if request.is_hex {
            hw_wallet::hex::decode(&request.message)?
        } else {
            request.message.into_bytes()
        };
        let result = self.sign_personal_message(request.path, message).await?;
        let mut signature = result.r;
        signature.extend(result.s);
        signature.push(result.v);
        Ok(crate::SignMessageResult {
            chain: crate::Chain::Ethereum,
            address: result.recovered_address,
            signature_formatted: format!("0x{}", hex::encode(&signature)),
            signature,
            signature_encoding: crate::SignatureEncoding::Hex,
            signed_data: None,
        })
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
    async fn shared_requests_reject_unsupported_options_before_accessing_device() {
        let handle = LedgerSessionHandle {
            client: Mutex::new(None),
            cancellation: watch::channel(0).0,
        };
        for (chain, chunkify, encoded_network) in [
            (crate::Chain::Bitcoin, false, None),
            (crate::Chain::Solana, true, None),
            (crate::Chain::Ethereum, true, None),
            (crate::Chain::Ethereum, false, Some(vec![1])),
        ] {
            assert!(matches!(
                handle
                    .get_address(crate::GetAddressRequest {
                        chain,
                        path: "m/44'/60'/0'/0/0".into(),
                        show_on_device: false,
                        include_public_key: false,
                        chunkify,
                        encoded_network: encoded_network.clone(),
                    })
                    .await,
                Err(HWCoreError::Unsupported(_))
            ));
            assert!(matches!(
                handle
                    .sign_message(crate::SignMessageRequest {
                        chain,
                        path: "m/44'/60'/0'/0/0".into(),
                        message: "hello".into(),
                        is_hex: false,
                        chunkify,
                        encoded_network,
                        signers: vec![],
                    })
                    .await,
                Err(HWCoreError::Unsupported(_))
            ));
        }
        let mut message = crate::SignMessageRequest {
            chain: crate::Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            message: "0x00".into(),
            is_hex: true,
            chunkify: false,
            signers: vec!["unexpected signer".into()],
            encoded_network: None,
        };
        assert!(matches!(
            handle.sign_message(message.clone()).await,
            Err(HWCoreError::Unsupported(_))
        ));
        message.signers.clear();
        message.message = "0xzz".into();
        assert!(matches!(
            handle.sign_message(message.clone()).await,
            Err(HWCoreError::Validation(_))
        ));
        message.message = "0x00".into();
        assert!(matches!(
            handle.sign_message(message).await,
            Err(HWCoreError::Disconnected(_))
        ));
    }

    #[tokio::test]
    async fn busy_and_closed_sessions_return_distinct_errors_without_queueing() {
        let handle = LedgerSessionHandle {
            client: Mutex::new(None),
            cancellation: watch::channel(0).0,
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
