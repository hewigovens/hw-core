use crate::bip32::HARDENED;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BitcoinPurpose {
    Legacy,
    NestedSegwit,
    Segwit,
    Taproot,
}

impl BitcoinPurpose {
    pub fn from_component(component: u32) -> Option<Self> {
        if component & HARDENED == 0 {
            return None;
        }
        match component & !HARDENED {
            44 => Some(Self::Legacy),
            49 => Some(Self::NestedSegwit),
            84 => Some(Self::Segwit),
            86 => Some(Self::Taproot),
            _ => None,
        }
    }
    pub fn descriptor(self) -> &'static str {
        match self {
            Self::Legacy => "pkh(@0/**)",
            Self::NestedSegwit => "sh(wpkh(@0/**))",
            Self::Segwit => "wpkh(@0/**)",
            Self::Taproot => "tr(@0/**)",
        }
    }
    pub fn message_header_offset(self) -> Option<u8> {
        match self {
            Self::Legacy => Some(0),
            Self::NestedSegwit => Some(4),
            Self::Segwit => Some(8),
            Self::Taproot => None,
        }
    }
}
