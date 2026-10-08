use hw_chain::Chain;

#[derive(Debug, Clone)]
pub struct GetAddressRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
    pub show_display: bool,
    pub chunkify: bool,
    pub encoded_network: Option<Vec<u8>>,
    pub include_public_key: bool,
}

impl GetAddressRequest {
    fn new(chain: Chain, path: Vec<u32>) -> Self {
        Self {
            chain,
            path,
            show_display: false,
            chunkify: false,
            encoded_network: None,
            include_public_key: false,
        }
    }

    pub fn ethereum(path: Vec<u32>) -> Self {
        Self::new(Chain::Ethereum, path)
    }

    pub fn bitcoin(path: Vec<u32>) -> Self {
        Self::new(Chain::Bitcoin, path)
    }

    pub fn solana(path: Vec<u32>) -> Self {
        Self::new(Chain::Solana, path)
    }

    pub fn with_show_display(mut self, value: bool) -> Self {
        self.show_display = value;
        self
    }

    pub fn with_chunkify(mut self, value: bool) -> Self {
        self.chunkify = value;
        self
    }

    pub fn with_include_public_key(mut self, value: bool) -> Self {
        self.include_public_key = value;
        self
    }
}

#[derive(Debug, Clone)]
pub struct GetAddressResponse {
    pub chain: Chain,
    pub address: String,
    pub mac: Option<Vec<u8>>,
    pub public_key: Option<String>,
}

/// Asks for the chain-formatted public key without on-device confirmation, like Suite does.
#[derive(Debug, Clone)]
pub struct GetPublicKeyRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
}

impl GetPublicKeyRequest {
    pub fn new(chain: Chain, path: Vec<u32>) -> Self {
        Self { chain, path }
    }
}
