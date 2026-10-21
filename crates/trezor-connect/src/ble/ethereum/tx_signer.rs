use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{
    ETH_DATA_CHUNK_SIZE, EncodedMessage, EthereumDefinitionAck, EthereumDefinitionRequest,
    EthereumTxAck, EthereumTxRequest, WireMessage,
};
use crate::thp::types::{EthSignTx, EthTxSignature};

#[derive(Debug)]
pub(in crate::ble) enum EthereumTxRequestHandling {
    Ack(EncodedMessage),
    Finished(EthTxSignature),
}

/// Answers the firmware's data and definition requests for one Ethereum transaction.
pub(in crate::ble) struct EthereumTxSigner<'a> {
    tx: &'a EthSignTx,
    data_offset: usize,
}

impl<'a> EthereumTxSigner<'a> {
    pub(in crate::ble) fn new(tx: &'a EthSignTx) -> Self {
        Self {
            tx,
            data_offset: tx.initial_chunk_len(),
        }
    }

    pub(in crate::ble) fn handle(
        &mut self,
        message_type: u16,
        payload: &[u8],
    ) -> BackendResult<EthereumTxRequestHandling> {
        match message_type {
            EthereumTxRequest::MESSAGE_TYPE => {
                self.handle_tx_request(EthereumTxRequest::from_message(message_type, payload)?)
            }
            EthereumDefinitionRequest::MESSAGE_TYPE => {
                let request = EthereumDefinitionRequest::from_message(message_type, payload)?;
                Ok(EthereumTxRequestHandling::Ack(
                    EthereumDefinitionAck::answer(self.tx, &request).to_message(),
                ))
            }
            _ => Err(BackendError::unexpected_signing_message(
                message_type,
                "Ethereum",
            )),
        }
    }

    fn handle_tx_request(
        &mut self,
        request: EthereumTxRequest,
    ) -> BackendResult<EthereumTxRequestHandling> {
        if let (Some(v), Some(r), Some(s)) = (
            request.signature_v,
            request.signature_r,
            request.signature_s,
        ) {
            return Ok(EthereumTxRequestHandling::Finished(EthTxSignature {
                v,
                r,
                s,
            }));
        }
        let Some(requested_len) = request.data_length else {
            return Err(BackendError::Transport(
                "EthereumTxRequest has neither signature nor data_length".into(),
            ));
        };
        let data = self.tx.data.as_slice();
        let requested_len = requested_len as usize;
        if requested_len > 0 && self.data_offset >= data.len() {
            return Err(BackendError::Transport(
                "device requested additional tx data beyond payload length".into(),
            ));
        }
        let end = (self.data_offset + requested_len.min(ETH_DATA_CHUNK_SIZE)).min(data.len());
        let ack = EthereumTxAck::new(&data[self.data_offset..end]).to_message();
        self.data_offset = end;
        Ok(EthereumTxRequestHandling::Ack(ack))
    }
}
