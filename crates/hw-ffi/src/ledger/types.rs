pub type LedgerModel = ledger_connect::LedgerModel;
#[uniffi::remote(Enum)]
pub enum LedgerModel {
    NanoX,
    Stax,
    Flex,
}

pub type LedgerAppInfo = ledger_connect::LedgerAppInfo;
#[uniffi::remote(Record)]
pub struct LedgerAppInfo {
    pub name: String,
    pub version: String,
}
