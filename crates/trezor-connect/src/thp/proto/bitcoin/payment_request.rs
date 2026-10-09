use prost::Message;

use super::TxAck;
use crate::thp::proto::wire::wire_messages;
use crate::thp::proto::{EncodedMessage, WireMessage};
use crate::thp::types::{BtcPaymentRequest, BtcPaymentRequestMemo};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TextMemoProto {
    #[prost(string, optional, tag = "1")]
    pub(crate) text: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RefundMemoProto {
    #[prost(string, required, tag = "1")]
    pub(crate) address: String,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub(crate) address_n: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub(crate) mac: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct CoinPurchaseMemoProto {
    #[prost(uint32, required, tag = "1")]
    pub(crate) coin_type: u32,
    #[prost(string, required, tag = "2")]
    pub(crate) amount: String,
    #[prost(string, required, tag = "3")]
    pub(crate) address: String,
    #[prost(uint32, repeated, packed = "false", tag = "4")]
    pub(crate) address_n: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "5")]
    pub(crate) mac: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TextDetailsMemoProto {
    #[prost(string, required, tag = "1")]
    pub(crate) title: String,
    #[prost(string, required, tag = "2")]
    pub(crate) text: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct PaymentRequestMemoProto {
    #[prost(message, optional, tag = "1")]
    pub(crate) text_memo: Option<TextMemoProto>,
    #[prost(message, optional, tag = "2")]
    pub(crate) refund_memo: Option<RefundMemoProto>,
    #[prost(message, optional, tag = "3")]
    pub(crate) coin_purchase_memo: Option<CoinPurchaseMemoProto>,
    #[prost(message, optional, tag = "4")]
    pub(crate) text_details_memo: Option<TextDetailsMemoProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BitcoinTxAckPaymentRequest {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub(crate) nonce: Option<Vec<u8>>,
    #[prost(string, required, tag = "2")]
    pub(crate) recipient_name: String,
    #[prost(message, repeated, tag = "3")]
    pub(crate) memos: Vec<PaymentRequestMemoProto>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub(crate) amount: Option<Vec<u8>>,
    #[prost(bytes = "vec", required, tag = "5")]
    pub(crate) signature: Vec<u8>,
}

wire_messages! {
    BitcoinTxAckPaymentRequest = 37,
}

impl From<&BtcPaymentRequestMemo> for PaymentRequestMemoProto {
    fn from(memo: &BtcPaymentRequestMemo) -> Self {
        match memo {
            BtcPaymentRequestMemo::Text { text } => Self {
                text_memo: Some(TextMemoProto {
                    text: Some(text.clone()),
                }),
                ..Default::default()
            },
            BtcPaymentRequestMemo::TextDetails { title, text } => Self {
                text_details_memo: Some(TextDetailsMemoProto {
                    title: title.clone(),
                    text: text.clone(),
                }),
                ..Default::default()
            },
            BtcPaymentRequestMemo::Refund { address, path, mac } => Self {
                refund_memo: Some(RefundMemoProto {
                    address: address.clone(),
                    address_n: path.clone(),
                    mac: mac.clone(),
                }),
                ..Default::default()
            },
            BtcPaymentRequestMemo::CoinPurchase {
                coin_type,
                amount,
                address,
                path,
                mac,
            } => Self {
                coin_purchase_memo: Some(CoinPurchaseMemoProto {
                    coin_type: *coin_type,
                    amount: amount.clone(),
                    address: address.clone(),
                    address_n: path.clone(),
                    mac: mac.clone(),
                }),
                ..Default::default()
            },
        }
    }
}

impl TxAck for BtcPaymentRequest {
    fn tx_ack(&self) -> EncodedMessage {
        BitcoinTxAckPaymentRequest {
            nonce: self.nonce.clone(),
            recipient_name: self.recipient_name.clone(),
            memos: self.memos.iter().map(Into::into).collect(),
            amount: self.amount.as_ref().map(|amount| amount.0.clone()),
            signature: self.signature.clone(),
        }
        .to_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::BtcPaymentRequestAmount;

    #[test]
    fn encodes_payment_request_with_every_memo_kind() {
        let request = BtcPaymentRequest {
            nonce: Some(vec![0x01, 0x02, 0x03]),
            recipient_name: "Test Merchant".to_string(),
            memos: vec![
                BtcPaymentRequestMemo::Text {
                    text: "Invoice #42".to_string(),
                },
                BtcPaymentRequestMemo::TextDetails {
                    title: "Details".to_string(),
                    text: "Extra context".to_string(),
                },
                BtcPaymentRequestMemo::Refund {
                    address: "tb1qrefund".to_string(),
                    path: vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 0],
                    mac: vec![0xaa, 0xbb],
                },
                BtcPaymentRequestMemo::CoinPurchase {
                    coin_type: 1,
                    amount: "0.025 BTC".to_string(),
                    address: "tb1qcoinpurchase".to_string(),
                    path: vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 1],
                    mac: vec![0xcc, 0xdd],
                },
            ],
            amount: Some(BtcPaymentRequestAmount::from_sats(900)),
            signature: vec![0xde, 0xad],
        };

        let encoded = request.tx_ack();
        assert_eq!(
            encoded.message_type,
            BitcoinTxAckPaymentRequest::MESSAGE_TYPE
        );

        let decoded = BitcoinTxAckPaymentRequest::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.nonce, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(decoded.recipient_name, "Test Merchant");
        assert_eq!(decoded.amount, Some(900u64.to_le_bytes().to_vec()));
        assert_eq!(decoded.signature, vec![0xde, 0xad]);
        assert_eq!(
            decoded.memos[0].text_memo.as_ref().unwrap().text.as_deref(),
            Some("Invoice #42")
        );
        assert_eq!(
            decoded.memos[1].text_details_memo.as_ref().unwrap().title,
            "Details"
        );
        assert_eq!(
            decoded.memos[2].refund_memo.as_ref().unwrap().address_n,
            vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 0]
        );
        assert_eq!(
            decoded.memos[3]
                .coin_purchase_memo
                .as_ref()
                .unwrap()
                .address_n,
            vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 1]
        );
    }
}
