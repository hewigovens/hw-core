use crate::eth::VerifiedSignature;
use crate::{WalletError, WalletResult};
use ledger_connect::EthereumSignature;
use sha3::{Digest, Keccak256};
use trezor_connect::thp::EthTxSignature;

#[derive(Debug, Clone)]
pub struct LedgerSigningResult {
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub signing_hash: Vec<u8>,
    pub recovered_address: String,
    pub signed_transaction: Option<Vec<u8>>,
    pub transaction_hash: Option<Vec<u8>>,
}

impl LedgerSigningResult {
    /// A normalized Ethereum message signature: r || s || v, with v = 27 or 28.
    pub fn message_signature(&self) -> WalletResult<Vec<u8>> {
        let v = match self.v {
            0 | 1 => self.v + 27,
            27 | 28 => self.v,
            _ => {
                return Err(WalletError::Verification(
                    "invalid Ethereum recovery id".into(),
                ));
            }
        };
        let mut signature = self.r.clone();
        signature.extend(&self.s);
        signature.push(v);
        Ok(signature)
    }

    pub(super) fn verify(
        signature: EthereumSignature,
        hash: [u8; 32],
        expected_address: &str,
    ) -> WalletResult<Self> {
        let raw = EthTxSignature {
            v: u32::from(signature.v),
            r: signature.r.clone(),
            s: signature.s.clone(),
        };
        let recovered = VerifiedSignature::recover_hash(hash, &raw)
            .map_err(|error| WalletError::Verification(error.to_string()))?;
        if !recovered
            .recovered_address
            .eq_ignore_ascii_case(expected_address)
        {
            return Err(WalletError::Verification(
                "Ledger signature does not match the requested account".into(),
            ));
        }
        Ok(Self {
            v: signature.v,
            r: signature.r,
            s: signature.s,
            signing_hash: hash.to_vec(),
            recovered_address: recovered.recovered_address,
            signed_transaction: None,
            transaction_hash: None,
        })
    }

    pub(super) fn with_transaction(mut self, unsigned: &[u8]) -> WalletResult<Self> {
        let parity = match self.v {
            0 | 1 => self.v,
            27 | 28 => self.v - 27,
            _ => {
                return Err(WalletError::Verification(
                    "invalid EIP-1559 recovery id".into(),
                ));
            }
        };
        let payload = unsigned
            .strip_prefix(&[2])
            .ok_or_else(|| WalletError::Signing("expected EIP-1559 payload".into()))?;
        let list = rlp::Rlp::new(payload);
        let mut signed = rlp::RlpStream::new_list(12);
        for index in 0..9 {
            signed.append_raw(
                list.at(index)
                    .map_err(|error| WalletError::Signing(error.to_string()))?
                    .as_raw(),
                1,
            );
        }
        signed.append(&parity);
        for scalar in [&self.r, &self.s] {
            let first = scalar
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(scalar.len());
            signed.append(&&scalar[first..]);
        }
        let mut envelope = vec![2];
        envelope.extend_from_slice(&signed.out());
        self.transaction_hash = Some(Keccak256::digest(&envelope).to_vec());
        self.signed_transaction = Some(envelope);
        self.v = parity;
        Ok(self)
    }
}
