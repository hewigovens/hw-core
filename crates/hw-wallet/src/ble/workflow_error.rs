use trezor_connect::thp::{BackendError, ThpWorkflowError};

use crate::error::WalletError;

pub(super) trait WorkflowErrorExt {
    fn is_transport_timeout(&self) -> bool;
    fn is_retryable_handshake(&self) -> bool;
    fn is_retryable_session(&self) -> bool;
    fn into_session_error(self) -> WalletError;
}

impl WorkflowErrorExt for ThpWorkflowError {
    fn is_transport_timeout(&self) -> bool {
        matches!(self, Self::Backend(BackendError::TransportTimeout))
    }

    fn is_retryable_handshake(&self) -> bool {
        matches!(
            self,
            Self::Backend(BackendError::DeviceLocked | BackendError::TransportBusy)
        )
    }

    fn is_retryable_session(&self) -> bool {
        matches!(
            self,
            Self::Backend(
                BackendError::DeviceBusy
                    | BackendError::DeviceLocked
                    | BackendError::PinExpected
                    | BackendError::DeviceFirmwareError
                    | BackendError::TransportBusy
                    | BackendError::SessionConfirmationRequired
            )
        )
    }

    fn into_session_error(self) -> WalletError {
        let message = match self {
            Self::Backend(BackendError::DeviceFirmwareError) => {
                "device reported a firmware error. Ensure the Trezor screen is unlocked and idle, then retry."
            }
            Self::Backend(BackendError::DeviceLocked | BackendError::PinExpected) => {
                "device is locked. Unlock the Trezor and retry."
            }
            Self::Backend(BackendError::DeviceBusy) => {
                "device is busy. Finish or cancel the action on the Trezor and retry."
            }
            other => return WalletError::Workflow(other),
        };
        WalletError::Workflow(ThpWorkflowError::Backend(BackendError::Device(
            message.into(),
        )))
    }
}
