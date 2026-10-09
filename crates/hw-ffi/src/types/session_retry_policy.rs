pub type SessionRetryPolicy = hw_wallet::ble::SessionRetryPolicy;

#[uniffi::remote(Record)]
pub struct SessionRetryPolicy {
    pub create_channel_attempts: u32,
    pub handshake_attempts: u32,
    pub create_session_attempts: u32,
    pub retry_delay_ms: u64,
}

#[uniffi::export]
pub fn session_retry_policy_default() -> SessionRetryPolicy {
    SessionRetryPolicy::default()
}
