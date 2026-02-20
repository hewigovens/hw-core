pub mod backend;
pub mod crypto;
pub mod eip712;
pub mod error;
pub mod proto;
pub mod state;
pub mod storage;
pub mod transport;
pub mod types;
pub mod wire;
pub mod workflow;

pub use backend::{BackendError, ThpBackend};
pub use error::{Result as WorkflowResult, ThpWorkflowError};
pub use hw_chain::Chain;
pub use state::{Phase, ThpState};
pub use storage::{FileStorage, HostSnapshot, StorageError, ThpStorage};
pub use thp_proto::hw::trezor::messages::thp as messages;
pub use transport::{ThpTransport, TransportError};
pub use types::{
    BtcInputScriptType, BtcOutputScriptType, BtcRefTx, BtcRefTxInput, BtcRefTxOutput, BtcSignInput,
    BtcSignOutput, BtcSignTx, CreateSessionRequest, Eip712StructMember, Eip712TypedData,
    EthAccessListEntry, GetAddressRequest, GetAddressResponse, HostConfig, PairingController,
    PairingDecision, PairingMethod, SignMessageRequest, SignMessageResponse, SignTxRequest,
    SignTxResponse, SignTypedDataPayload, SignTypedDataRequest, SignTypedDataResponse,
};
pub use workflow::ThpWorkflow;
