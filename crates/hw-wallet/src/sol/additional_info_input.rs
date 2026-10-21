use serde::Deserialize;
use trezor_connect::thp::{SolanaTxAdditionalInfo, SolanaTxTokenAccountInfo};

use crate::error::{WalletError, WalletResult};

#[derive(Debug, Deserialize)]
pub struct TxAdditionalInfoInput {
    #[serde(default)]
    pub token_accounts_infos: Vec<TxTokenAccountInfoInput>,
    /// Signed token definition for the first token account's mint, given as hex.
    #[serde(default, deserialize_with = "crate::hex::deserialize_optional")]
    pub encoded_token: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct TxTokenAccountInfoInput {
    pub base_address: String,
    pub token_program: String,
    pub token_mint: String,
    pub token_account: String,
}

impl TxAdditionalInfoInput {
    pub fn from_json(json: &str) -> WalletResult<Self> {
        serde_json::from_str(json).map_err(|err| {
            WalletError::Signing(format!("invalid solana additional info JSON: {err}"))
        })
    }
}

impl From<TxAdditionalInfoInput> for SolanaTxAdditionalInfo {
    fn from(input: TxAdditionalInfoInput) -> Self {
        Self {
            token_accounts_infos: input
                .token_accounts_infos
                .into_iter()
                .map(Into::into)
                .collect(),
            encoded_token: input.encoded_token,
        }
    }
}

impl From<TxTokenAccountInfoInput> for SolanaTxTokenAccountInfo {
    fn from(input: TxTokenAccountInfoInput) -> Self {
        Self {
            base_address: input.base_address,
            token_program: input.token_program,
            token_mint: input.token_mint,
            token_account: input.token_account,
        }
    }
}
