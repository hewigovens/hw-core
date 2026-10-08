use hw_chain::Chain;

pub const SOLANA_PUBLIC_KEY_LEN: usize = 32;

pub fn decode_solana_public_key(value: &str) -> Option<[u8; SOLANA_PUBLIC_KEY_LEN]> {
    bs58::decode(value).into_vec().ok()?.try_into().ok()
}

#[derive(Debug, Clone)]
pub struct SignMessageRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
    pub message: Vec<u8>,
    pub chunkify: bool,
    pub encoded_network: Option<Vec<u8>>,
    /// Solana OCMS v1 signers; empty means the workflow uses the signing key alone.
    pub solana_signers: Vec<[u8; SOLANA_PUBLIC_KEY_LEN]>,
}

impl SignMessageRequest {
    fn new(chain: Chain, path: Vec<u32>, message: Vec<u8>) -> Self {
        Self {
            chain,
            path,
            message,
            chunkify: false,
            encoded_network: None,
            solana_signers: Vec::new(),
        }
    }

    pub fn ethereum(path: Vec<u32>, message: Vec<u8>) -> Self {
        Self::new(Chain::Ethereum, path, message)
    }

    pub fn bitcoin(path: Vec<u32>, message: Vec<u8>) -> Self {
        Self::new(Chain::Bitcoin, path, message)
    }

    pub fn solana(
        path: Vec<u32>,
        message: String,
        signers: Vec<[u8; SOLANA_PUBLIC_KEY_LEN]>,
    ) -> Self {
        Self {
            solana_signers: signers,
            ..Self::new(Chain::Solana, path, message.into_bytes())
        }
    }

    pub fn with_chunkify(mut self, value: bool) -> Self {
        self.chunkify = value;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SignMessageResponse {
    pub chain: Chain,
    /// Empty when the signing address is unknown (Solana with several supplied signers).
    pub address: String,
    pub signature: Vec<u8>,
    /// Exact bytes the device signed (Solana OCMS v1 envelope).
    pub signed_data: Option<Vec<u8>>,
}
