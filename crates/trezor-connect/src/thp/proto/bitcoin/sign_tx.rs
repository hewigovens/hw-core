use prost::Message;

use super::address::COIN_NAME;
use crate::thp::proto::wire::wire_messages;
use crate::thp::proto::{ProtoMappingError, WireMessage};
use crate::thp::types::SignTxRequest;
use hw_chain::Chain;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinSignTx {
    #[prost(uint32, required, tag = "1")]
    outputs_count: u32,
    #[prost(uint32, required, tag = "2")]
    inputs_count: u32,
    #[prost(string, optional, tag = "3")]
    coin_name: Option<String>,
    #[prost(uint32, optional, tag = "4")]
    version: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    lock_time: Option<u32>,
    #[prost(bool, optional, tag = "13")]
    serialize: Option<bool>,
    #[prost(bool, optional, tag = "15")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BitcoinTxRequest {
    #[prost(enumeration = "BitcoinTxRequestTypeProto", optional, tag = "1")]
    request_type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    details: Option<BitcoinTxRequestDetails>,
    #[prost(message, optional, tag = "3")]
    serialized: Option<BitcoinTxRequestSerialized>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum BitcoinTxRequestTypeProto {
    Input = 0,
    Output = 1,
    Meta = 2,
    Finished = 3,
    ExtraData = 4,
    OrigInput = 5,
    OrigOutput = 6,
    PaymentReq = 7,
}

#[derive(Clone, PartialEq, Message)]
pub struct BitcoinTxRequestDetails {
    #[prost(uint32, optional, tag = "1")]
    request_index: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    tx_hash: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "3")]
    extra_data_len: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    extra_data_offset: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BitcoinTxRequestSerialized {
    #[prost(uint32, optional, tag = "1")]
    signature_index: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    serialized_tx: Option<Vec<u8>>,
}

wire_messages! {
    BitcoinSignTx = 15,
    BitcoinTxRequest = 21,
}

impl TryFrom<&SignTxRequest> for BitcoinSignTx {
    type Error = ProtoMappingError;

    fn try_from(request: &SignTxRequest) -> Result<Self, Self::Error> {
        let btc = request
            .btc
            .as_ref()
            .ok_or(ProtoMappingError::UnsupportedChain(Chain::Bitcoin))?;
        Ok(Self {
            outputs_count: btc.outputs.len() as u32,
            inputs_count: btc.inputs.len() as u32,
            coin_name: Some(COIN_NAME.to_string()),
            version: Some(btc.version),
            lock_time: Some(btc.lock_time),
            serialize: Some(true),
            chunkify: Some(btc.chunkify),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinTxRequestType {
    TxInput,
    TxOutput,
    TxMeta,
    TxFinished,
    TxExtraData,
    TxOrigInput,
    TxOrigOutput,
    TxPaymentReq,
}

impl TryFrom<i32> for BitcoinTxRequestType {
    type Error = ProtoMappingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match BitcoinTxRequestTypeProto::try_from(value) {
            Ok(BitcoinTxRequestTypeProto::Input) => Ok(Self::TxInput),
            Ok(BitcoinTxRequestTypeProto::Output) => Ok(Self::TxOutput),
            Ok(BitcoinTxRequestTypeProto::Meta) => Ok(Self::TxMeta),
            Ok(BitcoinTxRequestTypeProto::Finished) => Ok(Self::TxFinished),
            Ok(BitcoinTxRequestTypeProto::ExtraData) => Ok(Self::TxExtraData),
            Ok(BitcoinTxRequestTypeProto::OrigInput) => Ok(Self::TxOrigInput),
            Ok(BitcoinTxRequestTypeProto::OrigOutput) => Ok(Self::TxOrigOutput),
            Ok(BitcoinTxRequestTypeProto::PaymentReq) => Ok(Self::TxPaymentReq),
            Err(_) => Err(ProtoMappingError::InvalidEnum(value)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodedBitcoinTxRequest {
    pub request_type: Option<BitcoinTxRequestType>,
    pub request_index: Option<u32>,
    pub tx_hash: Option<Vec<u8>>,
    pub extra_data_len: Option<u32>,
    pub extra_data_offset: Option<u32>,
    pub signature_index: Option<u32>,
    pub signature: Option<Vec<u8>>,
    pub serialized_tx: Option<Vec<u8>>,
}

impl DecodedBitcoinTxRequest {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let request = BitcoinTxRequest::from_message(message_type, payload)?;
        let request_type = request
            .request_type
            .map(BitcoinTxRequestType::try_from)
            .transpose()?;
        let details = request.details.unwrap_or_default();
        let serialized = request.serialized.unwrap_or_default();
        Ok(Self {
            request_type,
            request_index: details.request_index,
            tx_hash: details.tx_hash,
            extra_data_len: details.extra_data_len,
            extra_data_offset: details.extra_data_offset,
            signature_index: serialized.signature_index,
            signature: serialized.signature,
            serialized_tx: serialized.serialized_tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::{
        BtcInputScriptType, BtcOutputScriptType, BtcSignInput, BtcSignOutput, BtcSignTx,
    };

    #[test]
    fn encodes_sign_tx_counts_and_serialize_flag() {
        let input = BtcSignInput {
            path: vec![0x8000_002c, 0x8000_0000, 0x8000_0000, 0, 0],
            prev_hash: vec![0x11; 32],
            prev_index: 1,
            amount: 1234,
            sequence: 0xffff_fffd,
            script_type: BtcInputScriptType::SpendWitness,
            multisig: None,
            script_sig: None,
            witness: None,
            orig_hash: None,
            orig_index: None,
        };
        let output = BtcSignOutput {
            address: Some("bc1qtest".to_string()),
            path: Vec::new(),
            amount: 1000,
            script_type: BtcOutputScriptType::PayToAddress,
            multisig: None,
            op_return_data: None,
            orig_hash: None,
            orig_index: None,
            payment_req_index: Some(0),
        };
        let mut request = SignTxRequest::bitcoin(BtcSignTx {
            version: 2,
            lock_time: 7,
            inputs: vec![input],
            outputs: vec![output.clone(), output],
            ref_txs: Vec::new(),
            orig_txs: Vec::new(),
            payment_reqs: Vec::new(),
            chunkify: true,
        });
        let (encoded, offset) = request.encode().unwrap();
        assert_eq!(offset, 0);
        assert_eq!(encoded.message_type, BitcoinSignTx::MESSAGE_TYPE);

        let decoded = BitcoinSignTx::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.inputs_count, 1);
        assert_eq!(decoded.outputs_count, 2);
        assert_eq!(decoded.version, Some(2));
        assert_eq!(decoded.lock_time, Some(7));
        assert_eq!(decoded.serialize, Some(true));
        assert_eq!(decoded.chunkify, Some(true));

        request.btc = None;
        assert!(matches!(
            request.encode(),
            Err(ProtoMappingError::UnsupportedChain(Chain::Bitcoin))
        ));
    }

    #[test]
    fn decodes_tx_request_details_and_serialized_parts() {
        let payload = BitcoinTxRequest {
            request_type: Some(BitcoinTxRequestTypeProto::Input as i32),
            details: Some(BitcoinTxRequestDetails {
                request_index: Some(0),
                tx_hash: Some(vec![0x11; 32]),
                extra_data_len: Some(3),
                extra_data_offset: Some(4),
            }),
            serialized: Some(BitcoinTxRequestSerialized {
                signature_index: Some(0),
                signature: Some(vec![0xAA; 64]),
                serialized_tx: Some(vec![0xBB, 0xCC]),
            }),
        }
        .encode_to_vec();

        let decoded =
            DecodedBitcoinTxRequest::decode(BitcoinTxRequest::MESSAGE_TYPE, &payload).unwrap();
        assert_eq!(
            decoded,
            DecodedBitcoinTxRequest {
                request_type: Some(BitcoinTxRequestType::TxInput),
                request_index: Some(0),
                tx_hash: Some(vec![0x11; 32]),
                extra_data_len: Some(3),
                extra_data_offset: Some(4),
                signature_index: Some(0),
                signature: Some(vec![0xAA; 64]),
                serialized_tx: Some(vec![0xBB, 0xCC]),
            }
        );

        let empty = DecodedBitcoinTxRequest::decode(BitcoinTxRequest::MESSAGE_TYPE, &[]).unwrap();
        assert_eq!(empty.request_type, None);
        assert_eq!(empty.signature, None);
    }

    #[test]
    fn rejects_unknown_tx_request_type_and_wrong_message() {
        let payload = BitcoinTxRequest {
            request_type: Some(99),
            details: None,
            serialized: None,
        }
        .encode_to_vec();
        assert!(matches!(
            DecodedBitcoinTxRequest::decode(BitcoinTxRequest::MESSAGE_TYPE, &payload),
            Err(ProtoMappingError::InvalidEnum(99))
        ));
        assert!(matches!(
            DecodedBitcoinTxRequest::decode(BitcoinSignTx::MESSAGE_TYPE, &payload),
            Err(ProtoMappingError::UnexpectedMessage(15))
        ));
    }
}
