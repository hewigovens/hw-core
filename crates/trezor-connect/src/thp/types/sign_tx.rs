use hw_chain::Chain;

use super::BtcSignTx;

#[derive(Debug, Clone)]
pub struct EthAccessListEntry {
    pub address: String,
    pub storage_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SignTxRequest {
    pub chain: Chain,
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
    pub btc: Option<BtcSignTx>,
}

impl SignTxRequest {
    fn new(chain: Chain, path: Vec<u32>) -> Self {
        Self {
            chain,
            path,
            nonce: vec![0],
            max_fee_per_gas: vec![0],
            max_priority_fee: vec![0],
            gas_limit: vec![0],
            to: String::new(),
            value: vec![0],
            data: Vec::new(),
            chain_id: 0,
            access_list: Vec::new(),
            chunkify: false,
            btc: None,
        }
    }

    pub fn ethereum(path: Vec<u32>, chain_id: u64) -> Self {
        Self {
            chain_id,
            ..Self::new(Chain::Ethereum, path)
        }
    }

    pub fn bitcoin(tx: BtcSignTx) -> Self {
        Self {
            chunkify: tx.chunkify,
            btc: Some(tx),
            ..Self::new(Chain::Bitcoin, Vec::new())
        }
    }

    pub fn solana(path: Vec<u32>, serialized_tx: Vec<u8>) -> Self {
        Self {
            data: serialized_tx,
            ..Self::new(Chain::Solana, path)
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

#[derive(Debug, Clone)]
pub struct SignTxResponse {
    pub chain: Chain,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    /// Per-input Bitcoin signatures, indexed by the device's `signature_index`.
    pub signatures: Vec<Vec<u8>>,
}
