use trezor_connect::thp::{BtcSignTx, SignTxRequest as ThpSignTxRequest, ThpBackend, ThpWorkflow};

use crate::errors::HWCoreError;
use crate::types::{
    AddressResult, BitcoinSignTxRequest, GetAddressRequest, SignMessageRequest, SignMessageResult,
    SignTxRequest, SignTxResult, SignTypedDataRequest, SignTypedDataResult,
};

/// Wallet requests that take and return FFI records.
#[allow(async_fn_in_trait)]
pub(super) trait WalletRequests {
    async fn request_address(
        &mut self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError>;
    async fn request_nonce(&mut self) -> Result<String, HWCoreError>;
    async fn request_tx_signature(
        &mut self,
        request: SignTxRequest,
    ) -> Result<SignTxResult, HWCoreError>;
    async fn request_bitcoin_tx_signature(
        &mut self,
        request: BitcoinSignTxRequest,
    ) -> Result<SignTxResult, HWCoreError>;
    async fn request_message_signature(
        &mut self,
        request: SignMessageRequest,
    ) -> Result<SignMessageResult, HWCoreError>;
    async fn request_typed_data_signature(
        &mut self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResult, HWCoreError>;
}

impl<B> WalletRequests for ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    async fn request_address(
        &mut self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError> {
        Ok(self.get_address(request.try_into()?).await?.into())
    }

    async fn request_nonce(&mut self) -> Result<String, HWCoreError> {
        let nonce = self.get_nonce().await?;
        Ok(format!("0x{}", hex::encode(nonce)))
    }

    async fn request_tx_signature(
        &mut self,
        request: SignTxRequest,
    ) -> Result<SignTxResult, HWCoreError> {
        self.request_thp_tx_signature(request.try_into()?).await
    }

    async fn request_bitcoin_tx_signature(
        &mut self,
        request: BitcoinSignTxRequest,
    ) -> Result<SignTxResult, HWCoreError> {
        let tx = BtcSignTx::try_from(request)?;
        self.request_thp_tx_signature(tx.into()).await
    }

    async fn request_message_signature(
        &mut self,
        request: SignMessageRequest,
    ) -> Result<SignMessageResult, HWCoreError> {
        Ok(self.sign_message(request.try_into()?).await?.into())
    }

    async fn request_typed_data_signature(
        &mut self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResult, HWCoreError> {
        self.sign_typed_data(request.try_into()?).await?.try_into()
    }
}

trait TxSignature {
    async fn request_thp_tx_signature(
        &mut self,
        request: ThpSignTxRequest,
    ) -> Result<SignTxResult, HWCoreError>;
}

impl<B> TxSignature for ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    async fn request_thp_tx_signature(
        &mut self,
        request: ThpSignTxRequest,
    ) -> Result<SignTxResult, HWCoreError> {
        let response = self.sign_tx(request.clone()).await?;
        Ok(SignTxResult::new(&request, response))
    }
}
