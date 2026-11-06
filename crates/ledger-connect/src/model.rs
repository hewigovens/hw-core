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

impl std::str::FromStr for LedgerModel {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "nano-x" => Ok(Self::NanoX),
            "stax" => Ok(Self::Stax),
            "flex" => Ok(Self::Flex),
            _ => Err("expected Ledger model nano-x, stax, or flex"),
        }
    }
}
