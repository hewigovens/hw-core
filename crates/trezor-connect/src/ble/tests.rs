use std::time::Duration;

use trezor_thp::channel::MAX_RETRANSMISSION_COUNT;

use super::link::{PacketLink, SESSION_ID};
use crate::thp::backend::BackendError;
use crate::thp::messages;
use crate::thp::proto::{MESSAGE_TYPE_SUCCESS, WireMessage};

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

    /// In-process device built from trezor-thp's device side, driven synchronously by host packets.
    pub struct FakeDevice {
        state: Option<State>,
        outbox: VecDeque<Vec<u8>>,
        pub busy: bool,
        pub replies: usize,
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
                        let (session, _message_type, _payload) =
                            ch.message_out().expect("device message_out");
                        ch.message_in(session, MESSAGE_TYPE_SUCCESS, &[])
                            .expect("device reply");
                        self.replies += 1;
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
        .receive_message(&mut channel, Duration::from_secs(5))
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
        device.receive_message(&mut channel, Duration::from_secs(5)),
    )
    .await
    .expect("busy retries must be bounded");

    assert!(matches!(result, Err(BackendError::TransportBusy)));
    assert_eq!(channel.sending_retry(), Some(MAX_RETRANSMISSION_COUNT - 1));
}
