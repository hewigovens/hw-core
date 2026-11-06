#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumAddress {
    pub address: String,
    pub public_key: Vec<u8>,
}
