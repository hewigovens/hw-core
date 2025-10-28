#[uniffi::export]
pub fn hw_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
