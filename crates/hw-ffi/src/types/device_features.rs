pub use trezor_connect::thp::DeviceFeatures;

/// Device identity, firmware version and passphrase settings from `Features`.
#[uniffi::remote(Record)]
pub struct DeviceFeatures {
    pub vendor: Option<String>,
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_version: u32,
    pub device_id: Option<String>,
    pub label: Option<String>,
    pub model: Option<String>,
    pub internal_model: Option<String>,
    pub bootloader_mode: bool,
    pub initialized: bool,
    pub unlocked: bool,
    pub pin_protection: bool,
    pub passphrase_protection: bool,
    pub passphrase_always_on_device: bool,
}
