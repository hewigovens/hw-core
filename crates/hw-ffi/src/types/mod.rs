mod address;
mod bitcoin_sign_tx;
mod ble_device_info;
mod button_request;
mod chain;
mod chain_metadata;
mod device_features;
mod eth_definitions;
mod ethereum_definitions_source;
mod host_config;
mod pairing_progress;
mod pairing_prompt;
mod session_retry_policy;
mod session_state;
mod sign_message;
mod sign_tx;
mod sign_typed_data;
mod signature_encoding;
mod solana_sign_tx;
mod uuid;
mod workflow_event;

pub use address::{AddressResult, GetAddressRequest};
pub use bitcoin_sign_tx::{
    BitcoinMultisig, BitcoinMultisigPubkey, BitcoinMultisigPubkeysOrder, BitcoinRefTx,
    BitcoinRefTxInput, BitcoinRefTxOutput, BitcoinSignTxRequest, BitcoinTxInput, BitcoinTxOutput,
};
pub use ble_device_info::BleDeviceInfo;
pub use button_request::{ButtonRequest, ButtonRequestCode};
pub use chain::{Chain, ChainConfig, chain_config};
pub(crate) use chain_metadata::ChainMetadataExt;
pub use device_features::DeviceFeatures;
pub use eth_definitions::{
    EthereumDefinitions, EthereumDisplayFormatDefinition, EthereumTokenDefinition,
};
pub use ethereum_definitions_source::EthereumDefinitionsSource;
pub use host_config::{HostConfig, KnownCredential, PairingMethod, host_config_new};
pub use pairing_progress::{PairingProgress, PairingProgressKind};
pub use pairing_prompt::{PairingPrompt, SessionHandshakeState};
pub use session_retry_policy::{SessionRetryPolicy, session_retry_policy_default};
pub(crate) use session_state::SessionStateExt;
pub use session_state::{SessionPhase, SessionState};
pub use sign_message::{SignMessageRequest, SignMessageResult};
pub use sign_tx::{AccessListEntry, SignTxRequest, SignTxResult};
pub use sign_typed_data::{SignTypedDataRequest, SignTypedDataResult};
pub use signature_encoding::SignatureEncoding;
pub use uuid::Uuid;
pub use workflow_event::{WorkflowEvent, WorkflowEventKind};

#[cfg(test)]
mod tests;
