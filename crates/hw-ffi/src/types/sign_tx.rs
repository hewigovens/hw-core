use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::btc::TxInput as BtcTxInput;
use hw_wallet::eth::{TxAccessListInput, TxInput as EthTxInput, VerifiedSignature};
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::sol::SolanaSignTxExt;
use trezor_connect::thp::{
    BtcSignTx, EthTxSignature, SignTxRequest as ThpSignTxRequest, SignTxResponse, SolanaSignTx,
};

use super::Chain;
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
                };
                Ok(tx
                    .into_sign_tx(path)?
                    .with_chunkify(request.chunkify)
                    .into())
            }
            Chain::Solana => {
                let path = parse_bip32_path(&request.path)?;
                let serialized_tx = decode_hex(&request.data)?;
                Ok(SolanaSignTx::from_serialized_tx(path, serialized_tx)?.into())
            }
            Chain::Bitcoin => {
                let tx = BtcTxInput::from_json(&request.data)?;
                Ok(BtcSignTx::try_from(tx)?.into())
            }
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
