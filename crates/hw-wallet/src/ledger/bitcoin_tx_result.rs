pub struct LedgerBitcoinTxResult {
    /// DER signatures in input order, without the SIGHASH_ALL suffix.
    pub signatures: Vec<Vec<u8>>,
    pub serialized_transaction: Vec<u8>,
    pub transaction_id: String,
}
