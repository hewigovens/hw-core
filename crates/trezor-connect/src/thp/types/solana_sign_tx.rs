#[derive(Debug, Clone)]
pub struct SolanaSignTx {
    pub path: Vec<u32>,
    pub serialized_tx: Vec<u8>,
}
