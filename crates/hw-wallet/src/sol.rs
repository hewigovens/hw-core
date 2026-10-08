use trezor_connect::thp::SolanaSignTx;

use crate::error::{WalletError, WalletResult};

pub const MIN_SERIALIZED_TX_BYTES: usize = 16;

const VERSION_PREFIX_MASK: u8 = 0x80;
const UNSUPPORTED_TX_VERSION: u8 = 1;

pub fn build_sign_tx_request(path: Vec<u32>, serialized_tx: Vec<u8>) -> WalletResult<SolanaSignTx> {
    if serialized_tx.len() < MIN_SERIALIZED_TX_BYTES {
        return Err(WalletError::SolanaTxTooShort {
            len: serialized_tx.len(),
            min: MIN_SERIALIZED_TX_BYTES,
        });
    }
    if tx_version(&serialized_tx) == Some(UNSUPPORTED_TX_VERSION) {
        return Err(WalletError::UnsupportedSolanaTxVersion(
            UNSUPPORTED_TX_VERSION,
        ));
    }
    Ok(SolanaSignTx {
        path,
        serialized_tx,
    })
}

// Mirrors Suite's isV1Transaction: v1 (SIMD-0385) puts the message first, so byte 0 is decisive.
fn tx_version(serialized_tx: &[u8]) -> Option<u8> {
    let first = *serialized_tx.first()?;
    (first & VERSION_PREFIX_MASK != 0).then_some(first & !VERSION_PREFIX_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletErrorKind;
    use crate::hex::decode;

    const SOL_TX_VERSIONS: &str = include_str!("../../../tests/data/solana/sol_tx_versions.json");

    fn fixture(key: &str) -> Vec<u8> {
        let fixtures: serde_json::Value = serde_json::from_str(SOL_TX_VERSIONS).unwrap();
        decode(fixtures[key].as_str().unwrap()).unwrap()
    }

    fn sol_path() -> Vec<u32> {
        vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
    }

    fn with_signatures(count: u8, message: Vec<u8>) -> Vec<u8> {
        let mut tx = vec![count];
        tx.extend(std::iter::repeat_n(0u8, 64 * usize::from(count)));
        tx.extend(message);
        tx
    }

    #[test]
    fn build_sign_tx_request_accepts_legacy_and_v0_messages() {
        for key in [
            "legacy_message",
            "v0_message_with_lookup_tables",
            "v0_message_without_lookup_tables",
        ] {
            let message = fixture(key);
            let request = build_sign_tx_request(sol_path(), message.clone())
                .unwrap_or_else(|err| panic!("{key} should be accepted: {err}"));
            assert_eq!(request.serialized_tx, message, "{key}");
            assert_eq!(request.path, sol_path(), "{key}");
        }
    }

    #[test]
    fn build_sign_tx_request_accepts_serialized_legacy_tx_with_signature_count_prefix() {
        let tx = with_signatures(2, fixture("legacy_message"));
        assert!(build_sign_tx_request(sol_path(), tx).is_ok());
    }

    #[test]
    fn build_sign_tx_request_rejects_v1_message_and_serialized_v1_tx() {
        let message = fixture("v1_message");
        let mut serialized_tx = message.clone();
        serialized_tx.extend([0u8; 64]);

        for tx in [message, serialized_tx] {
            let err = build_sign_tx_request(sol_path(), tx).unwrap_err();
            assert!(matches!(err, WalletError::UnsupportedSolanaTxVersion(1)));
            assert_eq!(err.kind(), WalletErrorKind::Validation);
        }
    }

    #[test]
    fn build_sign_tx_request_rejects_short_payloads() {
        for tx in [Vec::new(), vec![0x81], vec![0x01, 0x02, 0x03]] {
            let len = tx.len();
            let err = build_sign_tx_request(sol_path(), tx).unwrap_err();
            assert!(matches!(
                err,
                WalletError::SolanaTxTooShort { len: actual, min: MIN_SERIALIZED_TX_BYTES } if actual == len
            ));
            assert_eq!(err.kind(), WalletErrorKind::Validation);
        }
    }
}
