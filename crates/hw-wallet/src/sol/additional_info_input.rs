use serde::Deserialize;
use trezor_connect::thp::{SolanaTxAdditionalInfo, SolanaTxTokenAccountInfo};

use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

#[derive(Debug, Deserialize)]
pub struct TxAdditionalInfoInput {
    #[serde(default)]
    pub token_accounts_infos: Vec<TxTokenAccountInfoInput>,
    /// Hex of the signed token definition for the first token account's mint.
    pub encoded_token: Option<String>,
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

impl TryFrom<TxAdditionalInfoInput> for SolanaTxAdditionalInfo {
    type Error = WalletError;

    fn try_from(input: TxAdditionalInfoInput) -> WalletResult<Self> {
        Ok(Self {
            token_accounts_infos: input
                .token_accounts_infos
                .into_iter()
                .map(Into::into)
                .collect(),
            encoded_token: input.encoded_token.as_deref().map(decode).transpose()?,
        })
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
