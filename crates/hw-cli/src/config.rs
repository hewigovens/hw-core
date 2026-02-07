use std::env;
use std::path::PathBuf;

pub fn default_storage_path() -> PathBuf {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".hw-core").join("thp-host.json")
}

pub fn default_host_name() -> String {
    let device_name = whoami::devicename();
    let trimmed_device_name = device_name.trim();
    if !trimmed_device_name.is_empty() {
        return trimmed_device_name.to_string();
    }

    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    if let Ok(user) = env::var("USER") {
        let trimmed = user.trim();
        if !trimmed.is_empty() {
            return format!("{trimmed}-host");
        }
    }

    "hw-core-host".to_string()
}
