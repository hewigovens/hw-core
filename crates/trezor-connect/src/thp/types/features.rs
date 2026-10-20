/// Device identity and state reported by `Features`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceFeatures {
    pub vendor: Option<String>,
    /// Firmware version, or the bootloader version when `bootloader_mode` is set.
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_version: u32,
    /// Stable per-device identifier; changes only when the device is wiped.
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

impl DeviceFeatures {
    /// True when the reported version is at least `major.minor.patch`.
    pub fn version_at_least(&self, major: u32, minor: u32, patch: u32) -> bool {
        (self.major_version, self.minor_version, self.patch_version) >= (major, minor, patch)
    }
}
