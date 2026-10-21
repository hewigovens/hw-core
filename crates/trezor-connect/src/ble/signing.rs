use super::backend::BleBackend;
use super::bitcoin::{BitcoinTxRequestHandling, BitcoinTxSigner};
use super::ethereum::{EthereumTxRequestHandling, EthereumTxSigner};
use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{
    BitcoinTxRequest, DecodedBitcoinTxRequest, DecodedTypedDataResponse, EthereumTypedDataValueAck,
    SolanaTxSignature, WireMessage,
};
use crate::thp::types::{
    BtcSignTx, Eip712TypedData, EthSignTx, SignTxResponse, SignTypedDataResponse,
};

impl BleBackend {
    /// Answers the device's EIP-712 struct and value requests until it returns the signature.
    pub(super) async fn sign_eip712(
        &mut self,
        typed_data: &Eip712TypedData,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTypedDataResponse> {
        loop {
            let ack = match DecodedTypedDataResponse::decode(message_type, &payload)? {
                DecodedTypedDataResponse::Signature(response) => return Ok(response),
                DecodedTypedDataResponse::StructRequest(struct_request) => {
                    typed_data.struct_ack(&struct_request.name)?.to_message()
                }
                DecodedTypedDataResponse::ValueRequest(value_request) => {
                    let value = typed_data.member_value(&value_request.member_path)?;
                    EthereumTypedDataValueAck { value }.to_message()
                }
            };
            (message_type, payload) = self.request(ack).await?;
        }
    }

    pub(super) async fn sign_ethereum_tx(
        &mut self,
        tx: &EthSignTx,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTxResponse> {
        let mut signer = EthereumTxSigner::new(tx);
        loop {
            match signer.handle(message_type, &payload)? {
                EthereumTxRequestHandling::Ack(ack) => {
                    (message_type, payload) = self.request(ack).await?;
                }
                EthereumTxRequestHandling::Finished(signature) => {
                    return Ok(SignTxResponse::Ethereum(signature));
                }
            }
        }
    }

    pub(super) fn solana_signature(
        message_type: u16,
        payload: &[u8],
    ) -> BackendResult<SignTxResponse> {
        if message_type != SolanaTxSignature::MESSAGE_TYPE {
            return Err(BackendError::unexpected_signing_message(
                message_type,
                "Solana",
            ));
        }
        let signature = SolanaTxSignature::from_message(message_type, payload)?;
        Ok(SignTxResponse::Solana {
            signature: signature.signature,
        })
    }

    pub(super) async fn sign_bitcoin_tx(
        &mut self,
        btc: &BtcSignTx,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTxResponse> {
        let mut signer = BitcoinTxSigner::new(btc);
        loop {
            if message_type != BitcoinTxRequest::MESSAGE_TYPE {
                return Err(BackendError::unexpected_signing_message(
                    message_type,
                    "Bitcoin",
                ));
            }
            let tx_request = DecodedBitcoinTxRequest::decode(message_type, &payload)?;
            (message_type, payload) = match signer.handle(&tx_request)? {
                BitcoinTxRequestHandling::Ack(ack) => self.request(ack).await?,
                BitcoinTxRequestHandling::Continue => self.receive().await?,
                BitcoinTxRequestHandling::Finished => return Ok(signer.into_response()),
            };
        }
    }
}
