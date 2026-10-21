use super::Chain;
use crate::errors::HWCoreError;

/// Chain-specific metadata sent for another chain would be dropped silently, so the device would
/// sign without showing the context the caller supplied; reject it instead.
pub(crate) trait ChainMetadataExt {
    fn only_for<T>(
        self,
        owner: Chain,
        field: &str,
        value: Option<T>,
    ) -> Result<Option<T>, HWCoreError>;
}

impl ChainMetadataExt for Chain {
    fn only_for<T>(
        self,
        owner: Chain,
        field: &str,
        value: Option<T>,
    ) -> Result<Option<T>, HWCoreError> {
        match value {
            Some(_) if self != owner => Err(HWCoreError::Validation(format!(
                "{field} is only supported for {owner:?}, not {self:?}"
            ))),
            value => Ok(value),
        }
    }
}
