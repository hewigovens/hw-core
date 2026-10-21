use ble_transport::BleError;
use hw_wallet::{WalletError, WalletErrorKind};
use trezor_connect::thp::{BackendError, ThpWorkflowError};

/// FFI error; each variant is a failure class apps can switch on, `detail` is for display.
#[derive(Debug, uniffi::Error, thiserror::Error, Clone)]
#[uniffi(flat_error)]
pub enum HWCoreError {
    #[error("{0}")]
    Ble(String),
    #[error("{0}")]
    Workflow(String),
    #[error("{0}")]
    Device(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Timeout(String),
    #[error("{0}")]
    Unknown(String),
    /// Rejected on the device, or PIN entry cancelled.
    #[error("{0}")]
    ActionCancelled(String),
    /// The device is locked and expects PIN entry.
    #[error("{0}")]
    DeviceLocked(String),
    #[error("{0}")]
    DeviceBusy(String),
    /// The device must confirm this host's connection.
    #[error("{0}")]
    ConnectionConfirmationRequired(String),
    /// The device no longer knows this host; pair again.
    #[error("{0}")]
    PairingRequired(String),
    /// The BLE link dropped during the operation.
    #[error("{0}")]
    Disconnected(String),
    /// The firmware does not support the request; it may be too old.
    #[error("{0}")]
    Unsupported(String),
}

impl HWCoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Ble(_) => "BLE",
            Self::Workflow(_) => "WORKFLOW",
            Self::Device(_) => "DEVICE",
            Self::Validation(_) => "VALIDATION",
            Self::Timeout(_) => "TIMEOUT",
            Self::Unknown(_) => "UNKNOWN",
            Self::ActionCancelled(_) => "ACTION_CANCELLED",
            Self::DeviceLocked(_) => "DEVICE_LOCKED",
            Self::DeviceBusy(_) => "DEVICE_BUSY",
            Self::ConnectionConfirmationRequired(_) => "CONNECTION_CONFIRMATION_REQUIRED",
            Self::PairingRequired(_) => "PAIRING_REQUIRED",
            Self::Disconnected(_) => "DISCONNECTED",
            Self::Unsupported(_) => "UNSUPPORTED",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Ble(msg)
            | Self::Workflow(msg)
            | Self::Device(msg)
            | Self::Validation(msg)
            | Self::Timeout(msg)
            | Self::Unknown(msg)
            | Self::ActionCancelled(msg)
            | Self::DeviceLocked(msg)
            | Self::DeviceBusy(msg)
            | Self::ConnectionConfirmationRequired(msg)
            | Self::PairingRequired(msg)
            | Self::Disconnected(msg)
            | Self::Unsupported(msg) => msg,
        }
    }

    fn from_kind(kind: WalletErrorKind, message: String) -> Self {
        match kind {
            WalletErrorKind::Ble => Self::Ble(message),
            WalletErrorKind::Workflow => Self::Workflow(message),
            WalletErrorKind::Device => Self::Device(message),
            WalletErrorKind::Validation => Self::Validation(message),
            WalletErrorKind::Timeout => Self::Timeout(message),
            WalletErrorKind::ActionCancelled => Self::ActionCancelled(message),
            WalletErrorKind::DeviceLocked => Self::DeviceLocked(message),
            WalletErrorKind::DeviceBusy => Self::DeviceBusy(message),
            WalletErrorKind::ConnectionConfirmationRequired => {
                Self::ConnectionConfirmationRequired(message)
            }
            WalletErrorKind::PairingRequired => Self::PairingRequired(message),
            WalletErrorKind::Disconnected => Self::Disconnected(message),
            WalletErrorKind::Unsupported => Self::Unsupported(message),
        }
    }
}

impl From<BleError> for HWCoreError {
    fn from(error: BleError) -> Self {
        Self::from_kind(WalletErrorKind::from(&error), error.to_string())
    }
}

impl From<BackendError> for HWCoreError {
    fn from(error: BackendError) -> Self {
        Self::from_kind(WalletErrorKind::from(&error), error.to_string())
    }
}

impl From<ThpWorkflowError> for HWCoreError {
    fn from(error: ThpWorkflowError) -> Self {
        let kind = WalletErrorKind::from(&error);
        let message = match error {
            ThpWorkflowError::Backend(error) => error.to_string(),
            ThpWorkflowError::Storage(error) => error.to_string(),
            other => other.to_string(),
        };
        Self::from_kind(kind, message)
    }
}

impl From<WalletError> for HWCoreError {
    fn from(error: WalletError) -> Self {
        Self::from_kind(error.kind(), error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_wallet_failures_reach_distinct_ffi_variants() {
        let rejected = HWCoreError::from(ThpWorkflowError::Backend(BackendError::ActionCancelled));
        assert!(matches!(rejected, HWCoreError::ActionCancelled(_)));
        assert_eq!(rejected.code(), "ACTION_CANCELLED");

        let dropped = HWCoreError::from(WalletError::Ble(BleError::Disconnected));
        assert!(matches!(dropped, HWCoreError::Disconnected(_)));

        let locked = HWCoreError::from(WalletError::SessionUnavailable {
            hint: "device is locked. Unlock the Trezor and retry.",
            source: ThpWorkflowError::Backend(BackendError::PinExpected),
        });
        assert!(matches!(locked, HWCoreError::DeviceLocked(_)));
        assert_eq!(
            locked.detail(),
            "device is locked. Unlock the Trezor and retry."
        );
    }
}
