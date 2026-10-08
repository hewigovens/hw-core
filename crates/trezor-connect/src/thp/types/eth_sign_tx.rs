#[derive(Debug, Clone)]
pub struct EthAccessListEntry {
    pub address: String,
    pub storage_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthTxSignature {
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

/// EIP-1559 Ethereum transaction to sign.
#[derive(Debug, Clone)]
pub struct EthSignTx {
    pub path: Vec<u32>,
    pub nonce: Vec<u8>,
    pub max_fee_per_gas: Vec<u8>,
    pub max_priority_fee: Vec<u8>,
    pub gas_limit: Vec<u8>,
    pub to: String,
    pub value: Vec<u8>,
    pub data: Vec<u8>,
    pub chain_id: u64,
    pub access_list: Vec<EthAccessListEntry>,
    pub chunkify: bool,
}

impl EthSignTx {
    pub fn new(path: Vec<u32>, chain_id: u64) -> Self {
        Self {
            path,
            nonce: vec![0],
            max_fee_per_gas: vec![0],
            max_priority_fee: vec![0],
            gas_limit: vec![0],
            to: String::new(),
            value: vec![0],
            data: Vec::new(),
            chain_id,
            access_list: Vec::new(),
            chunkify: false,
        }
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_max_fee_per_gas(mut self, max_fee_per_gas: Vec<u8>) -> Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    pub fn with_max_priority_fee(mut self, max_priority_fee: Vec<u8>) -> Self {
        self.max_priority_fee = max_priority_fee;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: Vec<u8>) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_to(mut self, to: String) -> Self {
        self.to = to;
        self
    }

    pub fn with_value(mut self, value: Vec<u8>) -> Self {
        self.value = value;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_access_list(mut self, access_list: Vec<EthAccessListEntry>) -> Self {
        self.access_list = access_list;
        self
    }

    pub fn with_chunkify(mut self, chunkify: bool) -> Self {
        self.chunkify = chunkify;
        self
    }
}
