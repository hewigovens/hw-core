use crate::LedgerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumSignature {
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl EthereumSignature {
    pub(crate) const LENGTH: usize = 65;

    pub(crate) fn decode(response: &[u8]) -> Result<Self, LedgerError> {
        if response.len() != Self::LENGTH {
            return Err(LedgerError::Protocol("invalid Ethereum signature length"));
        }
        Ok(Self {
            v: response[0],
            r: response[1..33].to_vec(),
            s: response[33..].to_vec(),
        })
    }
}
