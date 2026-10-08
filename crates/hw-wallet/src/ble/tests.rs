use std::time::Duration;

use trezor_connect::thp::state::HandshakeCache;
use trezor_connect::thp::{BackendError, PairingMethod, Phase, ThpState, ThpWorkflowError};

use super::workflow_error::WorkflowErrorExt;
use super::*;

#[test]
fn device_locked_and_transport_busy_retry_handshake() {
    for (err, retryable) in [
        (BackendError::DeviceLocked, true),
        (BackendError::TransportBusy, true),
        (BackendError::PinExpected, false),
    ] {
        assert_eq!(
            ThpWorkflowError::Backend(err).is_retryable_handshake(),
            retryable
        );
    }
}

#[test]
fn session_phase_transition_sequence_progresses_to_ready() {
    let mut state = ThpState::new();
    assert_eq!(
        SessionPhase::from_state(&state, false),
        SessionPhase::NeedsChannel
    );

    state.set_handshake_cache(HandshakeCache {
        channel: 7,
        pairing_methods: vec![PairingMethod::CodeEntry],
    });
    assert_eq!(
        SessionPhase::from_state(&state, false),
        SessionPhase::NeedsHandshake
    );

    state.set_phase(Phase::Pairing);
    state.set_is_paired(false);
    assert_eq!(
        SessionPhase::from_state(&state, false),
        SessionPhase::NeedsPairingCode
    );

    state.set_is_paired(true);
    assert_eq!(
        SessionPhase::from_state(&state, false),
        SessionPhase::NeedsConnectionConfirmation
    );

    state.set_phase(Phase::Paired);
    assert_eq!(
        SessionPhase::from_state(&state, false),
        SessionPhase::NeedsSession
    );
    assert_eq!(SessionPhase::from_state(&state, true), SessionPhase::Ready);
}

#[test]
fn session_state_flags_follow_phase() {
    let pairing = SessionState::new(
        SessionPhase::NeedsPairingCode,
        Some("Enter code".to_string()),
    );
    assert!(pairing.can_pair_only);
    assert!(pairing.can_connect);
    assert!(!pairing.can_get_address);
    assert!(!pairing.can_sign_tx);
    assert!(pairing.requires_pairing_code);
    assert_eq!(pairing.prompt_message.as_deref(), Some("Enter code"));

    let ready = SessionState::new(SessionPhase::Ready, None);
    assert!(!ready.can_pair_only);
    assert!(!ready.can_connect);
    assert!(ready.can_get_address);
    assert!(ready.can_sign_tx);
    assert!(!ready.requires_pairing_code);
    assert!(ready.prompt_message.is_none());
}

#[test]
fn retry_policy_defaults_and_minimums() {
    for (policy, expected_attempts, expected_delay) in [
        (SessionRetryPolicy::default(), (3, 2, 3), 800),
        (
            SessionRetryPolicy {
                create_channel_attempts: 0,
                handshake_attempts: 0,
                create_session_attempts: 0,
                retry_delay_ms: 0,
            },
            (1, 1, 1),
            1,
        ),
    ] {
        assert_eq!(
            (
                policy.create_channel_attempts(),
                policy.handshake_attempts(),
                policy.create_session_attempts()
            ),
            expected_attempts
        );
        assert_eq!(policy.retry_delay(), Duration::from_millis(expected_delay));
    }
}
