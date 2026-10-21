use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use prost::Message;
use trezor_thp::channel::MAX_RETRANSMISSION_COUNT;

use super::device_prompts::DevicePrompts;
use super::errors::{FAILURE_ACTION_CANCELLED, FailureProto, MESSAGE_TYPE_FAILURE};
use super::link::{PacketLink, SESSION_ID};
use crate::thp::backend::BackendError;
use crate::thp::messages;
use crate::thp::proto::{
    ButtonAck, ButtonRequestProto, Cancel, GetNonce, MESSAGE_TYPE_SUCCESS, WireMessage,
};
use crate::thp::types::{ButtonRequest, ButtonRequestCode, DeviceEvent};

mod fake_device {
    use std::collections::VecDeque;

    use std::time::Duration;

    use trezor_thp::channel::buffered::Buffered;
    use trezor_thp::channel::host::Mux;
    use trezor_thp::channel::{PacketInResult, PairingState, device};
    use trezor_thp::credential::CredentialVerifier;

    use super::super::channel::{NoiseBackend, OpenChannel};
    use super::super::credentials::SharedCredentials;
    use super::super::link::PacketLink;
    use crate::thp::backend::BackendResult;
    use crate::thp::proto::MESSAGE_TYPE_SUCCESS;

    const DEVICE_KEY: [u8; 32] = [0x11; 32];
    // ThpDeviceProperties: protocol 2.0, pairing methods SkipPairing + CodeEntry.
    const DEVICE_PROPERTIES: &[u8] =
        b"\x0a\x04\x54\x33\x57\x31\x10\x00\x18\x02\x20\x00\x28\x01\x28\x02";
    pub const CHANNEL_ID: u16 = 0x1234;

    #[derive(Clone)]
    pub struct AlwaysUnpaired;

    impl CredentialVerifier for AlwaysUnpaired {
        fn verify(&self, _remote_static_pubkey: &[u8], _credential: &[u8]) -> PairingState {
            PairingState::Unpaired
        }
    }

    enum State {
        Mux(Box<Buffered<device::Mux<NoiseBackend>>>),
        Opening(Box<Buffered<device::ChannelOpen<AlwaysUnpaired, NoiseBackend>>>),
        Open(Box<Buffered<device::Channel<NoiseBackend>>>),
    }

    /// Device reply to a host message type; `None` keeps the device waiting (e.g. on a prompt).
    pub type Responder = Box<dyn FnMut(u16) -> Option<(u16, Vec<u8>)> + Send>;

    /// In-process device built from trezor-thp's device side, driven synchronously by host packets.
    pub struct FakeDevice {
        state: Option<State>,
        outbox: VecDeque<Vec<u8>>,
        pub busy: bool,
        pub replies: usize,
        pub received: Vec<u16>,
        pub respond: Responder,
    }

    impl FakeDevice {
        pub fn new() -> Self {
            let mut mux = Buffered::new(
                device::Mux::<NoiseBackend>::new(DEVICE_PROPERTIES).expect("device mux"),
            );
            mux.set_packet_len(PACKET_LEN);
            Self {
                state: Some(State::Mux(Box::new(mux))),
                outbox: VecDeque::new(),
                busy: false,
                replies: 0,
                received: Vec::new(),
                respond: Box::new(|_| Some((MESSAGE_TYPE_SUCCESS, Vec::new()))),
            }
        }

        /// True once the device has an established channel with no unacknowledged message.
        pub fn reply_acked(&self) -> bool {
            matches!(&self.state, Some(State::Open(ch)) if ch.sending_retry().is_none())
        }

        fn drain<C: trezor_thp::ChannelIO>(outbox: &mut VecDeque<Vec<u8>>, ch: &mut Buffered<C>) {
            while ch.packet_out_ready() {
                outbox.push_back(ch.packet_out().expect("device packet_out"));
            }
        }

        fn handle(&mut self, packet: &[u8]) {
            let state = self.state.take().expect("device state");
            self.state = Some(match state {
                State::Mux(mut mux) => {
                    mux.packet_in(packet);
                    Self::drain(&mut self.outbox, &mut mux);
                    if mux.channel_alloc_ready() {
                        let mut open = (*mux)
                            .map(|m| {
                                let mut m = m;
                                m.channel_alloc(CHANNEL_ID, AlwaysUnpaired)
                            })
                            .expect("device channel_alloc");
                        Self::drain(&mut self.outbox, &mut open);
                        State::Opening(Box::new(open))
                    } else {
                        State::Mux(mux)
                    }
                }
                State::Opening(mut open) => {
                    if let PacketInResult::HandshakeKeyRequired { .. } = open.packet_in(packet) {
                        open.set_static_key(&DEVICE_KEY).expect("device key");
                    }
                    Self::drain(&mut self.outbox, &mut *open);
                    if open.handshake_done() {
                        let channel = (*open).map(|o| o.complete()).expect("device complete");
                        State::Open(Box::new(channel))
                    } else {
                        State::Opening(open)
                    }
                }
                State::Open(mut ch) => {
                    if self.busy {
                        ch.send_error(trezor_thp::error::TransportError::TransportBusy);
                    } else if ch.packet_in(packet).got_message() {
                        let (session, message_type, _payload) =
                            ch.message_out().expect("device message_out");
                        self.received.push(message_type);
                        if let Some((reply_type, reply)) = (self.respond)(message_type) {
                            ch.message_in(session, reply_type, &reply)
                                .expect("device reply");
                            self.replies += 1;
                        }
                    }
                    Self::drain(&mut self.outbox, &mut *ch);
                    State::Open(ch)
                }
            });
        }
    }

    pub const PACKET_LEN: usize = 244;

    impl PacketLink for FakeDevice {
        async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()> {
            self.handle(packet);
            Ok(())
        }

        async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>> {
            match self.outbox.pop_front() {
                Some(packet) => Ok(Some(packet)),
                None => {
                    tokio::time::sleep(wait).await;
                    Ok(None)
                }
            }
        }
    }

    /// Opens a host channel to the fake device through the production pump.
    pub async fn open_channel(device: &mut FakeDevice) -> OpenChannel {
        let timeout = Duration::from_secs(5);
        let mut mux = Buffered::new(Mux::<NoiseBackend>::new());
        mux.set_packet_len(PACKET_LEN);
        mux.request_channel(false);
        device
            .pump(&mut mux, timeout, |_, r| r.got_channel())
            .await
            .expect("allocate");
        let credentials = SharedCredentials::default();
        credentials.prepare([0x22; 32], Vec::new());
        let mut open = mux.map(|m| m.complete(credentials)).expect("channel open");
        device
            .pump(&mut open, timeout, |o, _| o.handshake_done())
            .await
            .expect("handshake");
        open.map(|o| o.complete()).expect("channel")
    }
}

#[tokio::test(start_paused = true)]
async fn final_response_is_acknowledged_before_returning() {
    let mut device = fake_device::FakeDevice::new();
    let mut channel = fake_device::open_channel(&mut device).await;

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let (message_type, _) = device
        .receive_message(
            &mut channel,
            Duration::from_secs(5),
            &DevicePrompts::default(),
        )
        .await
        .unwrap();

    assert_eq!(message_type, MESSAGE_TYPE_SUCCESS);
    assert_eq!(device.replies, 1);
    assert!(
        device.reply_acked(),
        "device is still waiting for the host to ACK its reply"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_transport_busy_stops_at_retry_limit() {
    let mut device = fake_device::FakeDevice::new();
    let mut channel = fake_device::open_channel(&mut device).await;
    device.busy = true;

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(3600),
        device.receive_message(
            &mut channel,
            Duration::from_secs(5),
            &DevicePrompts::default(),
        ),
    )
    .await
    .expect("busy retries must be bounded");

    assert!(matches!(result, Err(BackendError::TransportBusy)));
    assert_eq!(channel.sending_retry(), Some(MAX_RETRANSMISSION_COUNT - 1));
}

const BUTTON_REQUEST_SIGN_TX: i32 = 8;

fn action_cancelled_failure() -> Vec<u8> {
    FailureProto {
        code: Some(FAILURE_ACTION_CANCELLED),
        message: None,
    }
    .encode_to_vec()
}

/// Device that prompts for every request and answers `Cancel` with `Failure(ActionCancelled)`.
fn prompting_device() -> fake_device::FakeDevice {
    let mut device = fake_device::FakeDevice::new();
    device.respond = Box::new(|message_type| match message_type {
        t if t == ButtonAck::MESSAGE_TYPE => None,
        t if t == Cancel::MESSAGE_TYPE => Some((MESSAGE_TYPE_FAILURE, action_cancelled_failure())),
        t if t == messages::ThpCreateNewSession::MESSAGE_TYPE => Some((
            ButtonRequestProto::MESSAGE_TYPE,
            ButtonRequestProto {
                code: Some(BUTTON_REQUEST_SIGN_TX),
                pages: None,
                name: Some("confirm_tx".into()),
            }
            .encode_to_vec(),
        )),
        _ => Some((MESSAGE_TYPE_SUCCESS, Vec::new())),
    });
    device
}

fn recording_prompts() -> (DevicePrompts, Arc<Mutex<Vec<DeviceEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let prompts = DevicePrompts {
        sink: Some(Arc::new(move |event| sink_events.lock().push(event))),
        ..DevicePrompts::default()
    };
    (prompts, events)
}

#[tokio::test(start_paused = true)]
async fn cancel_during_prompt_sends_cancel_and_keeps_channel_open() {
    let mut device = prompting_device();
    let mut channel = fake_device::open_channel(&mut device).await;
    let (prompts, events) = recording_prompts();
    let cancel = prompts.cancel.clone();

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let (result, ()) = tokio::join!(
        device.receive_message(&mut channel, Duration::from_secs(30), &prompts),
        async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel();
        }
    );

    let (message_type, payload) = result.unwrap();
    assert_eq!(message_type, MESSAGE_TYPE_FAILURE);
    assert!(matches!(
        BackendError::from_failure(&payload),
        BackendError::ActionCancelled
    ));
    assert_eq!(
        *events.lock(),
        vec![DeviceEvent::ButtonRequest(ButtonRequest {
            code: Some(ButtonRequestCode::SignTx),
            pages: None,
            name: Some("confirm_tx".into()),
        })]
    );
    assert!(!cancel.is_requested(), "cancel request must be consumed");

    channel
        .message_in(SESSION_ID, GetNonce::MESSAGE_TYPE, &[])
        .unwrap();
    let (message_type, _) = device
        .receive_message(&mut channel, Duration::from_secs(5), &prompts)
        .await
        .unwrap();
    assert_eq!(message_type, MESSAGE_TYPE_SUCCESS);
    assert_eq!(
        device.received,
        vec![
            messages::ThpCreateNewSession::MESSAGE_TYPE,
            ButtonAck::MESSAGE_TYPE,
            Cancel::MESSAGE_TYPE,
            GetNonce::MESSAGE_TYPE,
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn cancel_requested_before_prompt_applies_once_device_prompts() {
    let mut device = prompting_device();
    let mut channel = fake_device::open_channel(&mut device).await;
    let prompts = DevicePrompts::default();
    prompts.cancel.cancel();

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let (message_type, _) = tokio::time::timeout(
        Duration::from_secs(10),
        device.receive_message(&mut channel, Duration::from_secs(30), &prompts),
    )
    .await
    .expect("cancel must not wait for the prompt timeout")
    .unwrap();

    assert_eq!(message_type, MESSAGE_TYPE_FAILURE);
    assert_eq!(device.received.last(), Some(&Cancel::MESSAGE_TYPE));
}

#[tokio::test(start_paused = true)]
async fn response_already_received_wins_over_late_cancel() {
    // The device answers right after the ButtonAck, so its reply is queued when cancel lands.
    let mut device = fake_device::FakeDevice::new();
    device.respond = Box::new(|message_type| match message_type {
        t if t == messages::ThpCreateNewSession::MESSAGE_TYPE => Some((
            ButtonRequestProto::MESSAGE_TYPE,
            ButtonRequestProto::default().encode_to_vec(),
        )),
        _ => Some((MESSAGE_TYPE_SUCCESS, Vec::new())),
    });
    let mut channel = fake_device::open_channel(&mut device).await;
    let prompts = DevicePrompts::default();
    prompts.cancel.cancel();

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    for _ in 0..20 {
        let (message_type, _) = device
            .receive_message(&mut channel, Duration::from_secs(30), &prompts)
            .await
            .unwrap();
        assert_eq!(message_type, MESSAGE_TYPE_SUCCESS);
        assert!(
            !device.received.contains(&Cancel::MESSAGE_TYPE),
            "Cancel must not be sent once the device has replied"
        );
        prompts.cancel.cancel();
        channel
            .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn prompt_timeout_cancels_and_drains_before_failing() {
    let mut device = prompting_device();
    let mut channel = fake_device::open_channel(&mut device).await;
    let prompts = DevicePrompts::default();

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let result = device
        .receive_message(&mut channel, Duration::from_secs(30), &prompts)
        .await;
    assert!(matches!(result, Err(BackendError::TransportTimeout)));
    assert_eq!(device.received.last(), Some(&Cancel::MESSAGE_TYPE));

    // The cancelled request's Failure was drained, so the next request gets its own answer.
    channel
        .message_in(SESSION_ID, GetNonce::MESSAGE_TYPE, &[])
        .unwrap();
    let (message_type, _) = device
        .receive_message(&mut channel, Duration::from_secs(5), &prompts)
        .await
        .unwrap();
    assert_eq!(message_type, MESSAGE_TYPE_SUCCESS);
}
