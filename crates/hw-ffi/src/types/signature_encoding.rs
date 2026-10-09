use hw_wallet::message::SignatureEncoding as WalletSignatureEncoding;

#[derive(uniffi::Enum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    Hex,
    Base64,
}

impl From<WalletSignatureEncoding> for SignatureEncoding {
    fn from(encoding: WalletSignatureEncoding) -> Self {
        match encoding {
            WalletSignatureEncoding::Hex => Self::Hex,
            WalletSignatureEncoding::Base64 => Self::Base64,
        }
    }
}
