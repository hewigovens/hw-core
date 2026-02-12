pub mod manager;
pub mod profile;
pub mod session;

pub use btleplug::api::CentralState;
pub use manager::{BleManager, DiscoveredDevice, ScanBuilder, ScanEvent, ScanHandle, ScanOptions};
pub use profile::{BleError, BleProfile, DeviceInfo};
pub use session::{BleBackend, BleLink, BleSession};

pub type BleResult<T> = Result<T, BleError>;
