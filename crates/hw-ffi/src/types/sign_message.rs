use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::message::{NormalizedMessageSignature, SignMessageRequestExt};
use trezor_connect::thp::{
    SignMessageRequest as ThpSignMessageRequest, SignMessageResponse as ThpSignMessageResponse,
};

use super::{Chain, SignatureEncoding};
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignMessageRequest {
    pub chain: Chain,
    pub path: String,
    pub message: String,
    pub is_hex: bool,
    pub chunkify: bool,
    /// Solana only: base58 OCMS v1 signers; empty signs with the path's key alone.
    #[uniffi(default = [])]
    pub signers: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignMessageResult {
    pub chain: Chain,
    /// Empty for Solana messages with several supplied signers.
    pub address: String,
    pub signature: Vec<u8>,
    pub signature_formatted: String,
    pub signature_encoding: SignatureEncoding,
    /// Solana only: the serialized OCMS v1 message the device signed.
    #[uniffi(default = None)]
    pub signed_data: Option<Vec<u8>>,
}

impl TryFrom<SignMessageRequest> for ThpSignMessageRequest {
    type Error = HWCoreError;

    fn try_from(request: SignMessageRequest) -> Result<Self, Self::Error> {
        let path = parse_bip32_path(&request.path)?;
        Ok(Self::from_message(
            request.chain,
            path,
            &request.message,
            request.is_hex,
            request.chunkify,
            &request.signers,
        )?)
    }
}

impl From<ThpSignMessageResponse> for SignMessageResult {
    fn from(response: ThpSignMessageResponse) -> Self {
        let normalized = NormalizedMessageSignature::from(&response);
        Self {
            chain: response.chain,
            address: response.address,
            signature: response.signature,
            signature_formatted: normalized.value,
            signature_encoding: normalized.encoding.into(),
            signed_data: response.signed_data,
        }
    }
}
