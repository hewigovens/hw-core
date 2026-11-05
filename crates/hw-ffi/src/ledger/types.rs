pub type LedgerModel = ledger_connect::LedgerModel;
pub type LedgerEthereumAddress = ledger_connect::EthereumAddress;
pub type LedgerEthereumSignature = ledger_connect::EthereumSignature;

#[uniffi::remote(Enum)]
pub enum LedgerModel {
    NanoX,
    Stax,
    Flex,
}

#[uniffi::remote(Record)]
pub struct LedgerEthereumAddress {
    pub address: String,
    pub public_key: Vec<u8>,
}

#[uniffi::remote(Record)]
pub struct LedgerEthereumSignature {
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

pub type LedgerAppInfo = ledger_connect::LedgerAppInfo;
#[uniffi::remote(Record)]
pub struct LedgerAppInfo {
    pub name: String,
    pub version: String,
}

pub type LedgerSigningResult = hw_wallet::ledger::LedgerSigningResult;
#[uniffi::remote(Record)]
pub struct LedgerSigningResult {
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub signing_hash: Vec<u8>,
    pub recovered_address: String,
    pub signed_transaction: Option<Vec<u8>>,
    pub transaction_hash: Option<Vec<u8>>,
}
