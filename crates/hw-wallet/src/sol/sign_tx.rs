use trezor_connect::thp::SolanaSignTx;

use crate::error::{WalletError, WalletResult};

pub const MIN_SERIALIZED_TX_BYTES: usize = 16;

const VERSION_PREFIX_MASK: u8 = 0x80;
const SUPPORTED_VERSIONED_TX: u8 = 0;

pub trait SolanaSignTxExt: Sized {
    fn from_serialized_tx(path: Vec<u32>, serialized_tx: Vec<u8>) -> WalletResult<Self>;
}

impl SolanaSignTxExt for SolanaSignTx {
    fn from_serialized_tx(path: Vec<u32>, serialized_tx: Vec<u8>) -> WalletResult<Self> {
        if serialized_tx.len() < MIN_SERIALIZED_TX_BYTES {
            return Err(WalletError::SolanaTxTooShort {
                len: serialized_tx.len(),
                min: MIN_SERIALIZED_TX_BYTES,
            });
        }
        if let Some(version) = unsupported_tx_version(&serialized_tx) {
            return Err(WalletError::UnsupportedSolanaTxVersion(version));
        }
        Ok(Self {
            path,
            serialized_tx,
            additional_info: None,
        })
    }
}

// Mirrors Suite's isV1Transaction: v1 (SIMD-0385) puts the message first, so byte 0 is decisive.
// Suite's @solana/kit decoder also throws for versions above 1, so only legacy and v0 pass.
fn unsupported_tx_version(serialized_tx: &[u8]) -> Option<u8> {
    let first = *serialized_tx.first()?;
    let version = first & !VERSION_PREFIX_MASK;
    (first & VERSION_PREFIX_MASK != 0 && version != SUPPORTED_VERSIONED_TX).then_some(version)
}
