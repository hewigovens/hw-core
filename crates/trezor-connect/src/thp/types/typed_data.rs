use hw_chain::Chain;
use serde::{Deserialize, Serialize};

use super::Eip712TypedData;

#[derive(Debug, Clone)]
pub struct SignTypedDataRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
    pub payload: SignTypedDataPayload,
    pub encoded_network: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignTypedDataPayload {
    Hashes {
        domain_separator_hash: Vec<u8>,
        message_hash: Option<Vec<u8>>,
    },
    TypedData(Eip712TypedData),
}

impl SignTypedDataRequest {
    fn ethereum_payload(path: Vec<u32>, payload: SignTypedDataPayload) -> Self {
        Self {
            chain: Chain::Ethereum,
            path,
            payload,
            encoded_network: None,
        }
    }

    pub fn ethereum(
        path: Vec<u32>,
        domain_separator_hash: Vec<u8>,
        message_hash: Option<Vec<u8>>,
    ) -> Self {
        Self::ethereum_payload(
            path,
            SignTypedDataPayload::Hashes {
                domain_separator_hash,
                message_hash,
            },
        )
    }

    pub fn ethereum_typed_data(path: Vec<u32>, typed_data: Eip712TypedData) -> Self {
        Self::ethereum_payload(path, SignTypedDataPayload::TypedData(typed_data))
    }
}

#[derive(Debug, Clone)]
pub struct SignTypedDataResponse {
    pub chain: Chain,
    pub address: String,
    pub signature: Vec<u8>,
}
