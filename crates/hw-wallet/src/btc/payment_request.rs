use serde::Deserialize;
use trezor_connect::thp::{BtcPaymentRequest, BtcPaymentRequestAmount, BtcPaymentRequestMemo};

use super::sats::parse_sats;
use crate::bip32::parse_bip32_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

#[derive(Debug, Deserialize)]
pub struct TxInputPaymentRequest {
    pub nonce: Option<String>,
    pub recipient_name: String,
    #[serde(default)]
    pub memos: Vec<TxInputPaymentRequestMemo>,
    pub amount: Option<String>,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct TxInputPaymentRequestMemo {
    #[serde(rename = "type")]
    pub memo_type: String,
    pub title: Option<String>,
    pub text: Option<String>,
    pub address: Option<String>,
    pub path: Option<String>,
    pub mac: Option<String>,
    pub coin_type: Option<u32>,
    pub amount: Option<String>,
}

impl TryFrom<TxInputPaymentRequest> for BtcPaymentRequest {
    type Error = WalletError;

    fn try_from(request: TxInputPaymentRequest) -> WalletResult<Self> {
        let memos = request
            .memos
            .into_iter()
            .map(BtcPaymentRequestMemo::try_from)
            .collect::<WalletResult<_>>()?;
        Ok(Self {
            nonce: request.nonce.as_deref().map(decode).transpose()?,
            recipient_name: request.recipient_name,
            memos,
            amount: request
                .amount
                .as_deref()
                .map(parse_sats)
                .transpose()?
                .map(BtcPaymentRequestAmount::from_sats),
            signature: decode(&request.signature)?,
        })
    }
}

impl TryFrom<TxInputPaymentRequestMemo> for BtcPaymentRequestMemo {
    type Error = WalletError;

    fn try_from(memo: TxInputPaymentRequestMemo) -> WalletResult<Self> {
        let memo_type = memo.memo_type.as_str();
        let missing = |field: &str| {
            WalletError::Signing(format!(
                "bitcoin payment request {memo_type} memo requires {field}"
            ))
        };
        match memo_type {
            "text" => Ok(Self::Text {
                text: memo.text.ok_or_else(|| missing("text"))?,
            }),
            "text_details" => Ok(Self::TextDetails {
                title: memo.title.ok_or_else(|| missing("title"))?,
                text: memo.text.ok_or_else(|| missing("text"))?,
            }),
            "refund" => Ok(Self::Refund {
                address: memo.address.ok_or_else(|| missing("address"))?,
                path: parse_bip32_path(memo.path.as_deref().ok_or_else(|| missing("path"))?)?,
                mac: decode(memo.mac.as_deref().ok_or_else(|| missing("mac"))?)?,
            }),
            "coin_purchase" => Ok(Self::CoinPurchase {
                coin_type: memo.coin_type.ok_or_else(|| missing("coin_type"))?,
                amount: memo.amount.ok_or_else(|| missing("amount"))?,
                address: memo.address.ok_or_else(|| missing("address"))?,
                path: parse_bip32_path(memo.path.as_deref().ok_or_else(|| missing("path"))?)?,
                mac: decode(memo.mac.as_deref().ok_or_else(|| missing("mac"))?)?,
            }),
            other => Err(WalletError::Signing(format!(
                "unsupported bitcoin payment request memo type '{other}'"
            ))),
        }
    }
}
