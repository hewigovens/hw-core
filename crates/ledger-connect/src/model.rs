use ble_transport::BleProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerModel {
    NanoX,
    Stax,
    Flex,
}

impl LedgerModel {
    pub fn profile(self) -> BleProfile {
        match self {
            Self::NanoX => BleProfile::LEDGER_NANO_X,
            Self::Stax => BleProfile::LEDGER_STAX,
            Self::Flex => BleProfile::LEDGER_FLEX,
        }
    }
}
