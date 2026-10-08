use hw_chain::Chain;

use super::backend::BleBackend;
use super::bitcoin::{BitcoinTxRequestHandling, BitcoinTxSigner};
use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{
    BitcoinTxRequest, DecodedBitcoinTxRequest, DecodedTypedDataResponse, ETH_DATA_CHUNK_SIZE,
    EthereumTxAck, EthereumTxRequest, EthereumTypedDataValueAck, SolanaTxSignature, WireMessage,
};
use crate::thp::types::{
    BtcSignTx, Eip712TypedData, SignTxRequest, SignTxResponse, SignTypedDataResponse,
};

impl BleBackend {
    pub(super) async fn sign_transaction(
        &mut self,
        request: SignTxRequest,
    ) -> BackendResult<SignTxResponse> {
        let (encoded, initial_chunk_len) = request.encode()?;
        let (message_type, payload) = self.request(encoded).await?;
        match request.chain {
            Chain::Ethereum => {
                self.sign_ethereum_tx(&request.data, initial_chunk_len, message_type, payload)
                    .await
            }
            Chain::Solana => Self::solana_signature(message_type, &payload),
            Chain::Bitcoin => {
                let btc = request.btc.as_ref().ok_or_else(|| {
                    BackendError::Transport("missing Bitcoin signing payload".into())
                })?;
                self.sign_bitcoin_tx(btc, message_type, payload).await
            }
        }
    }

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

    async fn sign_ethereum_tx(
        &mut self,
        data: &[u8],
        mut data_offset: usize,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTxResponse> {
        loop {
            if message_type != EthereumTxRequest::MESSAGE_TYPE {
                return Err(BackendError::unexpected_signing_message(
                    message_type,
                    "Ethereum",
                ));
            }
            let tx_request = EthereumTxRequest::from_message(message_type, &payload)?;
            if let (Some(v), Some(r), Some(s)) = (
                tx_request.signature_v,
                tx_request.signature_r,
                tx_request.signature_s,
            ) {
                return Ok(SignTxResponse {
                    chain: Chain::Ethereum,
                    v,
                    r,
                    s,
                    signatures: Vec::new(),
                });
            }
            let Some(requested_len) = tx_request.data_length else {
                return Err(BackendError::Transport(
                    "EthereumTxRequest has neither signature nor data_length".into(),
                ));
            };
            let requested_len = requested_len as usize;
            if requested_len > 0 && data_offset >= data.len() {
                return Err(BackendError::Transport(
                    "device requested additional tx data beyond payload length".into(),
                ));
            }
            let end = (data_offset + requested_len.min(ETH_DATA_CHUNK_SIZE)).min(data.len());
            let ack = EthereumTxAck::new(&data[data_offset..end]).to_message();
            data_offset = end;
            (message_type, payload) = self.request(ack).await?;
        }
    }

    fn solana_signature(message_type: u16, payload: &[u8]) -> BackendResult<SignTxResponse> {
        if message_type != SolanaTxSignature::MESSAGE_TYPE {
            return Err(BackendError::unexpected_signing_message(
                message_type,
                "Solana",
            ));
        }
        let signature = SolanaTxSignature::from_message(message_type, payload)?;
        Ok(SignTxResponse {
            chain: Chain::Solana,
            v: 0,
            r: signature.signature,
            s: Vec::new(),
            signatures: Vec::new(),
        })
    }

    async fn sign_bitcoin_tx(
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
