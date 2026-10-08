#[cfg(target_vendor = "apple")]
#[path = "apple_acl.rs"]
mod acl;
#[cfg(all(unix, not(target_vendor = "apple")))]
#[path = "no_acl.rs"]
mod acl;
mod error;
mod file_storage;
mod snapshot;
mod thp_storage;
#[cfg(unix)]
mod unix;
#[cfg(not(unix))]
mod unsupported;

#[cfg(unix)]
use self::unix as platform;
#[cfg(not(unix))]
use unsupported as platform;

pub use error::StorageError;
pub use file_storage::FileStorage;
pub use snapshot::{CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION, HostSnapshot};
pub use thp_storage::ThpStorage;

#[cfg(all(test, target_vendor = "apple"))]
mod apple_tests;
#[cfg(all(test, unix))]
mod tests;
