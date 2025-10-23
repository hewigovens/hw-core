use crc32fast::Hasher;
use thiserror::Error;

const HEADER_LEN: usize = 8; // msg_id (4) + payload_len (4)
const CRC_LEN: usize = 4;
const MIN_MTU: usize = HEADER_LEN + CRC_LEN;
const MAX_PAYLOAD_LEN: usize = 1 << 20; // 1 MiB hard guard for now.

/// Logical THP transport frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThpFrame {
    pub msg_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThpCodecError {
    #[error("mtu_too_small")]
    MtuTooSmall,
    #[error("frame_too_large")]
    FrameTooLarge,
    #[error("crc_mismatch")]
    CrcMismatch,
}

#[derive(Debug, Default)]
pub struct ThpFrameDecoder {
    buffer: Vec<u8>,
}

impl ThpFrame {
    fn encode_inner(&self) -> Result<Vec<u8>, ThpCodecError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ThpCodecError::FrameTooLarge);
        }
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.payload.len() + CRC_LEN);
        bytes.extend_from_slice(&self.msg_id.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        let crc = hasher.finalize().to_be_bytes();
        bytes.extend_from_slice(&crc);
        Ok(bytes)
    }
}

impl ThpFrameDecoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    pub fn try_next(&mut self) -> Result<Option<ThpFrame>, ThpCodecError> {
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }

        let msg_id = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap());
        let payload_len = u32::from_be_bytes(self.buffer[4..8].try_into().unwrap()) as usize;

        if payload_len > MAX_PAYLOAD_LEN {
            self.buffer.clear();
            return Err(ThpCodecError::FrameTooLarge);
        }

        let total_len = HEADER_LEN + payload_len + CRC_LEN;
        if self.buffer.len() < total_len {
            return Ok(None);
        }

        let payload = self.buffer[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        let expected_crc = u32::from_be_bytes(
            self.buffer[HEADER_LEN + payload_len..total_len]
                .try_into()
                .unwrap(),
        );

        let mut hasher = Hasher::new();
        hasher.update(&self.buffer[..HEADER_LEN + payload_len]);
        let computed_crc = hasher.finalize();

        self.buffer.drain(..total_len);

        if computed_crc != expected_crc {
            return Err(ThpCodecError::CrcMismatch);
        }

        Ok(Some(ThpFrame { msg_id, payload }))
    }
}

pub fn encode_frame(frame: &ThpFrame, mtu: usize) -> Result<Vec<Vec<u8>>, ThpCodecError> {
    if mtu < MIN_MTU {
        return Err(ThpCodecError::MtuTooSmall);
    }

    let bytes = frame.encode_inner()?;
    let mut out = Vec::new();
    for chunk in bytes.chunks(mtu) {
        out.push(chunk.to_vec());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip(msg_id in any::<u32>(), payload in proptest::collection::vec(any::<u8>(), 0..1024), mtu in 16usize..256) {
            let frame = ThpFrame { msg_id, payload: payload.clone() };
            let chunks = encode_frame(&frame, mtu).unwrap();
            let mut decoder = ThpFrameDecoder::new();
            let mut result = None;
            for chunk in chunks {
                decoder.push(&chunk);
                if result.is_none() {
                    result = decoder.try_next().unwrap();
                }
            }
            let decoded = result.expect("frame should decode");
            prop_assert_eq!(decoded.msg_id, msg_id);
            prop_assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn detects_crc_mismatch() {
        let frame = ThpFrame {
            msg_id: 1,
            payload: vec![1, 2, 3],
        };
        let mut chunks = encode_frame(&frame, 32).unwrap();
        let last = chunks[0].len() - 1;
        chunks[0][last] ^= 0xFF;
        let mut decoder = ThpFrameDecoder::new();
        for chunk in chunks {
            decoder.push(&chunk);
        }
        let res = decoder.try_next();
        assert!(matches!(res, Err(ThpCodecError::CrcMismatch)));
    }
}
