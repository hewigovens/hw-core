use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::btc::TxInput as BtcTxInput;
use hw_wallet::eth::{TxAccessListInput, TxInput as EthTxInput, VerifiedSignature};
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::sol::SolanaSignTxExt;
use trezor_connect::thp::{
    BtcSignTx, EthTxSignature, SignTxRequest as ThpSignTxRequest, SignTxResponse, SolanaSignTx,
    SolanaTxAdditionalInfo,
};

use super::{Chain, EthereumDefinitions};
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct AccessListEntry {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTxRequest {
    pub chain: Chain,
    pub path: String,
    pub to: String,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub chain_id: u64,
    pub data: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee: String,
    pub access_list: Vec<AccessListEntry>,
    pub chunkify: bool,
    /// Ethereum only: network, token and display-format definitions for the device to show.
    #[uniffi(default = None)]
    pub eth_definitions: Option<EthereumDefinitions>,
    /// Solana only: token account infos and token definition for SPL transfers.
    #[uniffi(default = None)]
    pub solana_additional_info: Option<SolanaTxAdditionalInfo>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTxResult {
    pub chain: Chain,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    /// Per-input Bitcoin signatures, indexed by the device's `signature_index`.
    pub signatures: Vec<Vec<u8>>,
    pub tx_hash: Option<Vec<u8>>,
    pub recovered_address: Option<String>,
}

impl From<AccessListEntry> for TxAccessListInput {
    fn from(entry: AccessListEntry) -> Self {
        Self {
            address: entry.address,
            storage_keys: entry.storage_keys,
        }
    }
}

impl TryFrom<SignTxRequest> for ThpSignTxRequest {
    type Error = HWCoreError;

    fn try_from(request: SignTxRequest) -> Result<Self, Self::Error> {
        request.reject_other_chain_metadata()?;
        match request.chain {
            Chain::Ethereum => {
                let path = parse_bip32_path(&request.path)?;
                let tx = EthTxInput {
                    to: request.to,
                    value: request.value,
                    nonce: request.nonce,
                    gas_limit: request.gas_limit,
                    chain_id: request.chain_id,
                    data: request.data,
                    max_fee_per_gas: request.max_fee_per_gas,
                    max_priority_fee: request.max_priority_fee,
                    access_list: request.access_list.into_iter().map(Into::into).collect(),
                    definitions: request.eth_definitions.unwrap_or_default().into(),
                };
                Ok(tx
                    .into_sign_tx(path)?
                    .with_chunkify(request.chunkify)
                    .into())
            }
            Chain::Solana => {
                let path = parse_bip32_path(&request.path)?;
                let serialized_tx = decode_hex(&request.data)?;
                let mut tx = SolanaSignTx::from_serialized_tx(path, serialized_tx)?;
                tx.additional_info = request.solana_additional_info;
                Ok(tx.into())
            }
            Chain::Bitcoin => {
                let tx = BtcTxInput::from_json(&request.data)?;
                Ok(BtcSignTx::try_from(tx)?.into())
            }
        }
    }
}

impl SignTxRequest {
    /// Chain-specific display metadata on the wrong chain would be dropped silently, so the
    /// device would sign without showing the context the caller meant to supply.
    fn reject_other_chain_metadata(&self) -> Result<(), HWCoreError> {
        let field = match self.chain {
            Chain::Ethereum => self
                .solana_additional_info
                .as_ref()
                .map(|_| "solana_additional_info"),
            Chain::Solana => self.eth_definitions.as_ref().map(|_| "eth_definitions"),
            Chain::Bitcoin => self
                .eth_definitions
                .as_ref()
                .map(|_| "eth_definitions")
                .or(self
                    .solana_additional_info
                    .as_ref()
                    .map(|_| "solana_additional_info")),
        };
        match field {
            Some(field) => Err(HWCoreError::Validation(format!(
                "{field} is not supported for {:?} transactions",
                self.chain
            ))),
            None => Ok(()),
        }
    }
}

impl SignTxResult {
    pub(crate) fn new(request: &ThpSignTxRequest, response: SignTxResponse) -> Self {
        let verification = match (request, &response) {
            (ThpSignTxRequest::Ethereum(tx), SignTxResponse::Ethereum(signature)) => {
                VerifiedSignature::recover(tx, signature).ok()
            }
            (
                ThpSignTxRequest::Ethereum(_)
                | ThpSignTxRequest::Bitcoin(_)
                | ThpSignTxRequest::Solana(_),
                _,
            ) => None,
        };
        let (v, r, s, signatures) = match response {
            SignTxResponse::Ethereum(EthTxSignature { v, r, s }) => (v, r, s, Vec::new()),
            SignTxResponse::Bitcoin {
                signatures,
                last_signature,
            } => (0, last_signature, Vec::new(), signatures),
            SignTxResponse::Solana { signature } => (0, signature, Vec::new(), Vec::new()),
        };
        Self {
            chain: request.chain(),
            v,
            r,
            s,
            signatures,
            tx_hash: verification.as_ref().map(|sig| sig.tx_hash.to_vec()),
            recovered_address: verification.map(|sig| sig.recovered_address),
        }
    }
}
