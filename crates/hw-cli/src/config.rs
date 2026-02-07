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
    whoami::devicename()
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "hw-core-host".to_string())
}
