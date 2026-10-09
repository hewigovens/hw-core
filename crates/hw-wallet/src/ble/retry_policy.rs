use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRetryPolicy {
    pub create_channel_attempts: u32,
    pub handshake_attempts: u32,
    pub create_session_attempts: u32,
    pub retry_delay_ms: u64,
}

impl Default for SessionRetryPolicy {
    fn default() -> Self {
        Self {
            create_channel_attempts: 3,
            handshake_attempts: 2,
            create_session_attempts: 3,
            retry_delay_ms: 800,
        }
    }
}

impl SessionRetryPolicy {
    pub fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms.max(1))
    }

    pub fn create_channel_attempts(&self) -> usize {
        self.create_channel_attempts.max(1) as usize
    }

    pub fn handshake_attempts(&self) -> usize {
        self.handshake_attempts.max(1) as usize
    }

    pub fn create_session_attempts(&self) -> usize {
        self.create_session_attempts.max(1) as usize
    }
}
