use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use trezor_connect::thp::{EthAccessListEntry, EthSignTx};

use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

const EIP1559_TX_TYPE: u8 = 0x02;

pub trait EthSignTxExt {
    fn eip1559_sighash(&self) -> WalletResult<[u8; 32]>;
}

impl EthSignTxExt for EthSignTx {
    fn eip1559_sighash(&self) -> WalletResult<[u8; 32]> {
        let mut rlp = RlpStream::new_list(9);
        rlp.append_quantity(&self.chain_id.to_be_bytes());
        rlp.append_quantity(&self.nonce);
        rlp.append_quantity(&self.max_priority_fee);
        rlp.append_quantity(&self.max_fee_per_gas);
        rlp.append_quantity(&self.gas_limit);
        if self.to.is_empty() {
            rlp.append_quantity(&[]);
        } else {
            rlp.append(&decode_address(&self.to, "`to`")?.as_slice());
        }
        rlp.append_quantity(&self.value);
        rlp.append(&self.data.as_slice());
        rlp.append_access_list(&self.access_list)?;

        let mut typed_payload = vec![EIP1559_TX_TYPE];
        typed_payload.extend_from_slice(&rlp.out());
        Ok(Keccak256::digest(typed_payload).into())
    }
}

trait RlpStreamExt {
    fn append_quantity(&mut self, value: &[u8]);
    fn append_access_list(&mut self, entries: &[EthAccessListEntry]) -> WalletResult<()>;
}

impl RlpStreamExt for RlpStream {
    // RLP quantities drop leading zero bytes; zero itself encodes as the empty string.
    fn append_quantity(&mut self, value: &[u8]) {
        let first = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len());
        self.append(&&value[first..]);
    }

    fn append_access_list(&mut self, entries: &[EthAccessListEntry]) -> WalletResult<()> {
        self.begin_list(entries.len());
        for entry in entries {
            let address = decode_address(&entry.address, "access-list")?;
            self.begin_list(2);
            self.append(&address.as_slice());
            self.begin_list(entry.storage_keys.len());
            for key in &entry.storage_keys {
                self.append(&key.as_slice());
            }
        }
        Ok(())
    }
}

fn decode_address(value: &str, label: &str) -> WalletResult<Vec<u8>> {
    let address = decode(value)?;
    if address.len() != 20 {
        return Err(WalletError::Signing(format!(
            "invalid {label} address length {}; expected 20 bytes",
            address.len()
        )));
    }
    Ok(address)
}
