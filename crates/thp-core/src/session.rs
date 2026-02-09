use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use snow::Builder as NoiseBuilder;
use thp_codec::{ThpFrame, ThpFrameDecoder, encode_frame};
use tokio::{sync::Mutex, time};
use tracing::debug;

use crate::{
    error::ThpError,
    link::Link,
    trust::{TrustStore, TrustedPeer},
};

#[derive(Debug, Clone)]
pub enum HandshakeEvent {
    BondingRequired,
    ShowNumericCode { code: String },
}

pub struct HandshakeOpts {
    pub device_id: String,
    pub handshake_timeout: Duration,
    pub trust_store: Arc<dyn TrustStore>,
    pub app_id: Option<Vec<u8>>,
}

pub struct ThpSession {
    device_id: String,
    mtu: usize,
    tx_counter: AtomicU32,
    rx_expected: AtomicU32,
    transport: Mutex<snow::TransportState>,
}

impl ThpSession {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub async fn handshake<L: Link + Send>(
        link: &mut L,
        opts: HandshakeOpts,
        cb: impl Fn(HandshakeEvent) + Send,
    ) -> Result<Self, ThpError> {
        // Surface a hint to UI that Numeric Comparison may be requested shortly.
        cb(HandshakeEvent::BondingRequired);

        let HandshakeOpts {
            device_id,
            handshake_timeout,
            trust_store,
            app_id,
        } = opts;

        let params = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let host_keys = builder.generate_keypair()?;
        let mut noise = builder
            .local_private_key(&host_keys.private)?
            .build_initiator()?;

        let mtu = link.mtu();
        let mut decoder = ThpFrameDecoder::new();

        let mut local_msg_id = 0u32;
        let mut remote_msg_id = 1u32;

        // Message 1 (handshake initiation)
        let mut out = vec![0u8; 256];
        let init_payload = app_id.as_deref().unwrap_or(&[]);
        let written = noise.write_message(init_payload, &mut out)?;
        out.truncate(written);
        send_frame(link, mtu, local_msg_id, out).await?;
        local_msg_id = local_msg_id.wrapping_add(2);

        // Message 2 (device response)
        let response = receive_frame(link, &mut decoder, handshake_timeout).await?;
        ensure_msg_id(remote_msg_id, response.msg_id)?;
        remote_msg_id = remote_msg_id.wrapping_add(2);

        let mut noise_buf = vec![0u8; 256];
        let read = noise.read_message(&response.payload, &mut noise_buf)?;
        noise_buf.truncate(read);

        let remote_static = noise
            .get_remote_static()
            .map(|k| k.to_vec())
            .ok_or(ThpError::MissingRemoteStatic)?;

        if let Some(trusted) = trust_store.get(&device_id).await.map_err(ThpError::from)?
            && trusted.peer_static_key != remote_static
        {
            return Err(ThpError::PeerStaticMismatch);
        }

        // Message 3 (handshake completion)
        let mut completion = vec![0u8; 256];
        let len = noise.write_message(&[], &mut completion)?;
        completion.truncate(len);
        send_frame(link, mtu, local_msg_id, completion).await?;
        local_msg_id = local_msg_id.wrapping_add(2);

        // Promote to transport mode.
        let transport = noise.into_transport_mode()?;

        let peer = TrustedPeer {
            device_id: device_id.clone(),
            peer_static_key: remote_static,
            established_at_ms: epoch_ms(),
        };
        trust_store.put(peer).await.map_err(ThpError::from)?;

        Ok(Self {
            device_id,
            mtu,
            tx_counter: AtomicU32::new(local_msg_id),
            rx_expected: AtomicU32::new(remote_msg_id),
            transport: Mutex::new(transport),
        })
    }

    pub async fn request<L: Link + Send>(
        &self,
        link: &mut L,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ThpError> {
        let msg_id = self.tx_counter.fetch_add(2, Ordering::SeqCst);

        let mut writer = self.transport.lock().await;
        let mut ciphertext = vec![0u8; payload.len() + 256];
        let written = writer.write_message(payload, &mut ciphertext)?;
        ciphertext.truncate(written);
        drop(writer);

        let frame = ThpFrame {
            msg_id,
            payload: ciphertext,
        };
        let chunks = encode_frame(&frame, self.mtu)?;
        for chunk in chunks {
            link.write(&chunk).await.map_err(ThpError::from)?;
        }

        let expected = self.rx_expected.load(Ordering::SeqCst);
        let mut decoder = ThpFrameDecoder::new();
        loop {
            if let Some(frame) = decoder.try_next()? {
                ensure_msg_id(expected, frame.msg_id)?;
                self.rx_expected
                    .store(expected.wrapping_add(2), Ordering::SeqCst);

                let mut reader = self.transport.lock().await;
                let mut plaintext = vec![0u8; frame.payload.len().max(64)];
                let read = reader.read_message(&frame.payload, &mut plaintext)?;
                plaintext.truncate(read);
                return Ok(plaintext);
            }

            let chunk = time::timeout(timeout, link.read())
                .await
                .map_err(|_| ThpError::Timeout)?
                .map_err(ThpError::from)?;
            decoder.push(&chunk);
        }
    }
}

async fn receive_frame<L: Link + Send>(
    link: &mut L,
    decoder: &mut ThpFrameDecoder,
    timeout: Duration,
) -> Result<ThpFrame, ThpError> {
    loop {
        if let Some(frame) = decoder.try_next()? {
            return Ok(frame);
        }

        let chunk = time::timeout(timeout, link.read())
            .await
            .map_err(|_| ThpError::Timeout)?
            .map_err(ThpError::from)?;
        decoder.push(&chunk);
    }
}

async fn send_frame<L: Link + Send>(
    link: &mut L,
    mtu: usize,
    msg_id: u32,
    payload: Vec<u8>,
) -> Result<(), ThpError> {
    let frame = ThpFrame { msg_id, payload };
    let chunks = encode_frame(&frame, mtu)?;
    for chunk in chunks {
        link.write(&chunk).await.map_err(ThpError::from)?;
    }
    Ok(())
}

fn ensure_msg_id(expected: u32, actual: u32) -> Result<(), ThpError> {
    if expected != actual {
        debug!("unexpected message id: expected {expected}, got {actual}");
        Err(ThpError::UnexpectedMsgId { expected, actual })
    } else {
        Ok(())
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::trust::MemoryTrustStore;
    use tokio::sync::mpsc;

    struct MockLink {
        mtu: usize,
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
    }

    impl Link for MockLink {
        async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
            self.tx.send(chunk.to_vec()).await?;
            Ok(())
        }

        async fn read(&mut self) -> anyhow::Result<Vec<u8>> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("channel closed"))
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }

    fn channel_pair(capacity: usize, mtu: usize) -> (MockLink, MockLink) {
        let (tx_a, rx_b) = mpsc::channel(capacity);
        let (tx_b, rx_a) = mpsc::channel(capacity);
        let host = MockLink {
            mtu,
            rx: rx_a,
            tx: tx_a,
        };
        let device = MockLink {
            mtu,
            rx: rx_b,
            tx: tx_b,
        };
        (host, device)
    }

    async fn run_device(mut link: MockLink) {
        let params = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();
        let builder = NoiseBuilder::new(params);
        let device_keys = builder.generate_keypair().unwrap();
        let mut noise = builder
            .local_private_key(&device_keys.private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut decoder = ThpFrameDecoder::new();
        let mut remote_msg_id = 0u32;

        // Receive message 1
        let incoming = receive_frame(&mut link, &mut decoder, Duration::from_secs(1))
            .await
            .unwrap();
        ensure_msg_id(remote_msg_id, incoming.msg_id).unwrap();
        remote_msg_id = remote_msg_id.wrapping_add(2);
        let mut buf = vec![0u8; 256];
        let read = noise.read_message(&incoming.payload, &mut buf).unwrap();
        buf.truncate(read);

        // Send message 2
        let mut response = vec![0u8; 256];
        let wrote = noise.write_message(&[], &mut response).unwrap();
        response.truncate(wrote);
        let mtu = link.mtu();
        send_frame(&mut link, mtu, 1, response).await.unwrap();

        // Receive message 3
        let incoming = receive_frame(&mut link, &mut decoder, Duration::from_secs(1))
            .await
            .unwrap();
        ensure_msg_id(remote_msg_id, incoming.msg_id).unwrap();
        let mut buf = vec![0u8; 256];
        let read = noise.read_message(&incoming.payload, &mut buf).unwrap();
        buf.truncate(read);

        let mut transport = noise.into_transport_mode().unwrap();
        let mut next_msg_id = 3u32;

        // Handle one request -> response echo
        loop {
            let incoming = receive_frame(&mut link, &mut decoder, Duration::from_secs(1))
                .await
                .unwrap();
            let mut plain = vec![0u8; incoming.payload.len()];
            let read = transport
                .read_message(&incoming.payload, &mut plain)
                .unwrap();
            plain.truncate(read);
            let mut response = vec![0u8; plain.len() + 16];
            let wrote = transport.write_message(&plain, &mut response).unwrap();
            response.truncate(wrote);
            let mtu = link.mtu();
            let msg_id = next_msg_id;
            next_msg_id = next_msg_id.wrapping_add(2);
            send_frame(&mut link, mtu, msg_id, response).await.unwrap();
        }
    }

    #[tokio::test]
    async fn handshake_and_request_roundtrip() {
        let (mut host_link, device_link) = channel_pair(4, 128);
        tokio::spawn(run_device(device_link));

        let session = ThpSession::handshake(
            &mut host_link,
            HandshakeOpts {
                device_id: "device-123".into(),
                handshake_timeout: Duration::from_secs(1),
                trust_store: Arc::new(MemoryTrustStore::default()),
                app_id: None,
            },
            |_| {},
        )
        .await
        .expect("handshake");

        let payload = b"hello-thp";
        let response = session
            .request(&mut host_link, payload, Duration::from_secs(1))
            .await
            .expect("roundtrip");
        assert_eq!(response, payload);
    }
}
