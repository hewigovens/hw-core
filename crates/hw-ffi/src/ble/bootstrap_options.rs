use hw_wallet::ble::SessionBootstrapOptions;

use crate::types::SessionRetryPolicy;

pub(super) trait SessionBootstrapOptionsExt {
    fn from_ffi(try_to_unlock: bool, retry_policy: Option<SessionRetryPolicy>) -> Self;
}

impl SessionBootstrapOptionsExt for SessionBootstrapOptions {
    fn from_ffi(try_to_unlock: bool, retry_policy: Option<SessionRetryPolicy>) -> Self {
        Self {
            try_to_unlock,
            retry_policy: retry_policy.unwrap_or_default(),
            ..Self::default()
        }
    }
}
