use trezor_connect::thp::{SolanaTxAdditionalInfo, SolanaTxTokenAccountInfo};

/// Token context for SPL transfers; `encoded_token` is the signed definition of the first mint.
#[uniffi::remote(Record)]
pub struct SolanaTxAdditionalInfo {
    pub token_accounts_infos: Vec<SolanaTxTokenAccountInfo>,
    pub encoded_token: Option<Vec<u8>>,
}

/// Base58 addresses of an associated token account, its owner, token program and mint.
#[uniffi::remote(Record)]
pub struct SolanaTxTokenAccountInfo {
    pub base_address: String,
    pub token_program: String,
    pub token_mint: String,
    pub token_account: String,
}
