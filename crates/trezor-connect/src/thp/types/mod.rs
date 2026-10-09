mod address;
mod btc;
mod channel;
mod credential;
mod eip712;
mod eth_sign_tx;
mod handshake;
mod host_config;
mod pairing;
mod session;
mod sign_message;
mod sign_tx;
mod solana_sign_tx;
mod typed_data;

pub use address::{GetAddressRequest, GetAddressResponse, GetPublicKeyRequest};
pub use btc::{
    BtcHDNode, BtcHDNodePath, BtcInputScriptType, BtcMultisig, BtcMultisigPubkeysOrder, BtcOrigTx,
    BtcOutputScriptType, BtcPaymentRequest, BtcPaymentRequestAmount, BtcPaymentRequestMemo,
    BtcRefTx, BtcRefTxInput, BtcRefTxOutput, BtcSignInput, BtcSignOutput, BtcSignTx,
};
pub use channel::{CreateChannelRequest, CreateChannelResponse, ThpProperties};
pub use credential::{CredentialRequest, CredentialResponse, KnownCredential};
pub use eip712::{Eip712StructMember, Eip712TypedData};
pub use eth_sign_tx::{EthAccessListEntry, EthSignTx, EthTxSignature};
pub use handshake::{HandshakeCompletionState, HandshakeRequest, HandshakeResponse};
pub use host_config::HostConfig;
pub use pairing::{
    CodeEntryChallengeRequest, CodeEntryChallengeResponse, PairingController, PairingDecision,
    PairingMethod, PairingPrompt, PairingRequest, PairingRequestApproved, PairingTagRequest,
    PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
};
pub use session::{CreateSessionRequest, CreateSessionResponse};
pub use sign_message::{
    SOLANA_PUBLIC_KEY_LEN, SignMessageRequest, SignMessageResponse, decode_solana_public_key,
};
pub use sign_tx::{SignTxRequest, SignTxResponse};
pub use solana_sign_tx::SolanaSignTx;
pub use typed_data::{SignTypedDataPayload, SignTypedDataRequest, SignTypedDataResponse};
