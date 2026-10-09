use hw_wallet::bip32::parse_bip32_path;
use trezor_connect::thp::{
    GetAddressRequest as ThpGetAddressRequest, GetAddressResponse as ThpGetAddressResponse,
};

use super::Chain;
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct GetAddressRequest {
    pub chain: Chain,
    pub path: String,
    pub show_on_device: bool,
    pub include_public_key: bool,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AddressResult {
    pub chain: Chain,
    pub address: String,
    pub mac: Option<String>,
    pub public_key: Option<String>,
}

impl TryFrom<GetAddressRequest> for ThpGetAddressRequest {
    type Error = HWCoreError;

    fn try_from(request: GetAddressRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            chain: request.chain,
            path: parse_bip32_path(&request.path)?,
            show_display: request.show_on_device,
            chunkify: request.chunkify,
            encoded_network: None,
            include_public_key: request.include_public_key,
        })
    }
}

impl From<ThpGetAddressResponse> for AddressResult {
    fn from(response: ThpGetAddressResponse) -> Self {
        Self {
            chain: response.chain,
            address: response.address,
            mac: response.mac.map(|mac| format!("0x{}", hex::encode(mac))),
            public_key: response.public_key,
        }
    }
}
