use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::message::{SignTypedDataRequestExt, SignTypedDataResponseExt};
use trezor_connect::thp::{
    SignTypedDataRequest as ThpSignTypedDataRequest,
    SignTypedDataResponse as ThpSignTypedDataResponse,
};

use super::{Chain, SignatureEncoding};
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTypedDataRequest {
    pub chain: Chain,
    pub path: String,
    pub domain_separator_hash: String,
    pub message_hash: Option<String>,
    #[uniffi(default = None)]
    pub data_json: Option<String>,
    #[uniffi(default = true)]
    pub metamask_v4_compat: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTypedDataResult {
    pub chain: Chain,
    pub address: String,
    pub signature: Vec<u8>,
    pub signature_formatted: String,
    pub signature_encoding: SignatureEncoding,
}

impl TryFrom<SignTypedDataRequest> for ThpSignTypedDataRequest {
    type Error = HWCoreError;

    fn try_from(request: SignTypedDataRequest) -> Result<Self, Self::Error> {
        if request.chain != Chain::Ethereum {
            return Err(HWCoreError::Validation(
                "typed-data signing currently supports Ethereum only".to_string(),
            ));
        }

        let path = parse_bip32_path(&request.path)?;
        let is_present = |hash: &String| !hash.trim().is_empty();
        let domain_separator_hash = Some(request.domain_separator_hash).filter(is_present);
        let message_hash = request.message_hash.filter(is_present);

        Ok(Self::from_eip712(
            path,
            request.data_json.as_deref(),
            domain_separator_hash.as_deref(),
            message_hash.as_deref(),
            request.metamask_v4_compat,
        )?)
    }
}

impl TryFrom<ThpSignTypedDataResponse> for SignTypedDataResult {
    type Error = HWCoreError;

    fn try_from(response: ThpSignTypedDataResponse) -> Result<Self, Self::Error> {
        let signature_formatted = response.formatted_signature()?;
        Ok(Self {
            chain: response.chain,
            address: response.address,
            signature: response.signature,
            signature_formatted,
            signature_encoding: SignatureEncoding::Hex,
        })
    }
}
