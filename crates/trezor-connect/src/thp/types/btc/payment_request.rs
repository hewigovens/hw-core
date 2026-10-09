#[derive(Debug, Clone)]
pub enum BtcPaymentRequestMemo {
    Text {
        text: String,
    },
    TextDetails {
        title: String,
        text: String,
    },
    Refund {
        address: String,
        path: Vec<u32>,
        mac: Vec<u8>,
    },
    CoinPurchase {
        coin_type: u32,
        amount: String,
        address: String,
        path: Vec<u32>,
        mac: Vec<u8>,
    },
}

/// SLIP-24-encoded payment request amount bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcPaymentRequestAmount(pub Vec<u8>);

impl BtcPaymentRequestAmount {
    pub fn from_sats(amount: u64) -> Self {
        Self(amount.to_le_bytes().to_vec())
    }
}

/// Caller-supplied SLIP-24 payment request data for `TXPAYMENTREQ`.
#[derive(Debug, Clone)]
pub struct BtcPaymentRequest {
    pub nonce: Option<Vec<u8>>,
    pub recipient_name: String,
    pub memos: Vec<BtcPaymentRequestMemo>,
    pub amount: Option<BtcPaymentRequestAmount>,
    pub signature: Vec<u8>,
}
