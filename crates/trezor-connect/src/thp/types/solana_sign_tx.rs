#[derive(Debug, Clone)]
pub struct SolanaSignTx {
    pub path: Vec<u32>,
    pub serialized_tx: Vec<u8>,
    pub additional_info: Option<SolanaTxAdditionalInfo>,
}

/// Context the device cannot derive from the transaction alone, used to display token transfers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SolanaTxAdditionalInfo {
    pub token_accounts_infos: Vec<SolanaTxTokenAccountInfo>,
    /// Signed token definition for the first token account's mint, as served by Trezor.
    pub encoded_token: Option<Vec<u8>>,
}

/// Base58 addresses tying an associated token account to its owner, program and mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaTxTokenAccountInfo {
    pub base_address: String,
    pub token_program: String,
    pub token_mint: String,
    pub token_account: String,
}

impl SolanaSignTx {
    pub fn with_additional_info(mut self, additional_info: SolanaTxAdditionalInfo) -> Self {
        self.additional_info = Some(additional_info);
        self
    }
}
