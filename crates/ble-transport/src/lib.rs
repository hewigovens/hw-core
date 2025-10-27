pub mod manager;
pub mod profile;
pub mod session;

pub use manager::{BleManager, DiscoveredDevice};
pub use profile::{BleError, BleProfile, DeviceInfo, KnownProfiles};
pub use session::{BleBackend, BleLink, BleSession};

pub type BleResult<T> = Result<T, BleError>;
