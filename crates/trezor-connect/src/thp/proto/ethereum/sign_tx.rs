use prost::Message;

use crate::thp::proto::wire::wire_messages;
use crate::thp::types::EthSignTx;

/// Largest `data` slice sent per EIP-1559 sign request or `TxAck`.
pub const ETH_DATA_CHUNK_SIZE: usize = 1024;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumAccessList {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    storage_keys: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumSignTxEip1559 {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    nonce: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    max_gas_fee: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    max_priority_fee: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    gas_limit: Option<Vec<u8>>,
    #[prost(string, optional, tag = "6")]
    to: Option<String>,
    #[prost(bytes = "vec", optional, tag = "7")]
    value: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "8")]
    data_initial_chunk: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    data_length: Option<u32>,
    #[prost(uint64, required, tag = "10")]
    chain_id: u64,
    #[prost(message, repeated, tag = "11")]
    access_list: Vec<EthereumAccessList>,
    #[prost(bool, optional, tag = "13")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTxRequest {
    #[prost(uint32, optional, tag = "1")]
    pub data_length: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub signature_v: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub signature_r: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub signature_s: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTxAck {
    #[prost(bytes = "vec", optional, tag = "1")]
    data_chunk: Option<Vec<u8>>,
}

wire_messages! {
    EthereumSignTxEip1559 = 452,
    EthereumTxRequest = 59,
    EthereumTxAck = 60,
}

impl EthSignTx {
    /// How many bytes of `data` the initial sign request carries.
    pub(crate) fn initial_chunk_len(&self) -> usize {
        self.data.len().min(ETH_DATA_CHUNK_SIZE)
    }
}

impl From<&EthSignTx> for EthereumSignTxEip1559 {
    fn from(request: &EthSignTx) -> Self {
        let initial_chunk = &request.data[..request.initial_chunk_len()];
        Self {
            path: request.path.clone(),
            nonce: Some(request.nonce.clone()),
            max_gas_fee: Some(request.max_fee_per_gas.clone()),
            max_priority_fee: Some(request.max_priority_fee.clone()),
            gas_limit: Some(request.gas_limit.clone()),
            to: (!request.to.is_empty()).then(|| request.to.clone()),
            value: Some(request.value.clone()),
            data_initial_chunk: (!initial_chunk.is_empty()).then(|| initial_chunk.to_vec()),
            data_length: Some(request.data.len() as u32),
            chain_id: request.chain_id,
            access_list: request
                .access_list
                .iter()
                .map(|entry| EthereumAccessList {
                    address: entry.address.clone(),
                    storage_keys: entry.storage_keys.clone(),
                })
                .collect(),
            chunkify: Some(request.chunkify),
        }
    }
}

impl EthereumTxAck {
    pub fn new(data_chunk: &[u8]) -> Self {
        Self {
            data_chunk: Some(data_chunk.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::proto::WireMessage;
    use crate::thp::types::{EthAccessListEntry, SignTxRequest};

    #[derive(Clone, PartialEq, Message)]
    struct EthereumSignTxEip1559PaymentReqProbe {
        #[prost(bytes = "vec", optional, tag = "14")]
        payment_req: Option<Vec<u8>>,
    }

    const PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

    #[test]
    fn encodes_sign_tx_without_data_or_payment_request() {
        let request = EthSignTx::new(PATH.to_vec(), 1)
            .with_nonce(vec![1])
            .with_max_fee_per_gas(vec![0x3b, 0x9a, 0xca, 0x00])
            .with_max_priority_fee(vec![0x59, 0x68, 0x2f, 0x00])
            .with_gas_limit(vec![0x52, 0x08])
            .with_to("0xdead".into())
            .with_value(vec![0])
            .with_access_list(vec![EthAccessListEntry {
                address: "0xbeef".into(),
                storage_keys: vec![vec![1; 32]],
            }]);

        assert_eq!(request.initial_chunk_len(), 0);
        let encoded = SignTxRequest::from(request).encode();
        assert_eq!(encoded.message_type, EthereumSignTxEip1559::MESSAGE_TYPE);

        let decoded = EthereumSignTxEip1559::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, Some(vec![1]));
        assert_eq!(decoded.to.as_deref(), Some("0xdead"));
        assert_eq!(decoded.data_length, Some(0));
        assert!(decoded.data_initial_chunk.is_none());
        assert_eq!(decoded.access_list[0].address, "0xbeef");
        assert_eq!(decoded.chunkify, Some(false));

        let probe =
            EthereumSignTxEip1559PaymentReqProbe::decode(encoded.payload.as_slice()).unwrap();
        assert!(probe.payment_req.is_none());
    }

    #[test]
    fn encodes_initial_data_chunk_and_reports_its_length() {
        for (data_len, chunk_len) in [
            (10, 10),
            (ETH_DATA_CHUNK_SIZE, ETH_DATA_CHUNK_SIZE),
            (2048, ETH_DATA_CHUNK_SIZE),
        ] {
            let request = EthSignTx::new(PATH.to_vec(), 1).with_data(vec![0xAB; data_len]);

            assert_eq!(request.initial_chunk_len(), chunk_len);

            let encoded = SignTxRequest::from(request).encode();

            let decoded = EthereumSignTxEip1559::decode(encoded.payload.as_slice()).unwrap();
            assert!(decoded.to.is_none());
            assert_eq!(decoded.data_length, Some(data_len as u32));
            assert_eq!(decoded.data_initial_chunk, Some(vec![0xAB; chunk_len]));
        }
    }

    #[test]
    fn decodes_tx_request_and_encodes_tx_ack() {
        let payload = EthereumTxRequest {
            data_length: Some(1024),
            signature_v: Some(1),
            signature_r: Some(vec![0xAA; 32]),
            signature_s: None,
        }
        .encode_to_vec();
        let decoded =
            EthereumTxRequest::from_message(EthereumTxRequest::MESSAGE_TYPE, &payload).unwrap();
        assert_eq!(decoded.data_length, Some(1024));
        assert_eq!(decoded.signature_v, Some(1));
        assert_eq!(decoded.signature_r, Some(vec![0xAA; 32]));
        assert!(decoded.signature_s.is_none());

        let encoded = EthereumTxAck::new(&[0xCC; 512]).to_message();
        assert_eq!(encoded.message_type, EthereumTxAck::MESSAGE_TYPE);
        let decoded = EthereumTxAck::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.data_chunk, Some(vec![0xCC; 512]));
    }
}
