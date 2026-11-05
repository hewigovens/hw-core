use crate::LedgerError;

pub(crate) struct BleFrames;

impl BleFrames {
    pub fn encode(apdu: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, LedgerError> {
        if !(6..=255).contains(&mtu) {
            return Err(LedgerError::Protocol("invalid BLE frame size"));
        }
        let length =
            u16::try_from(apdu.len()).map_err(|_| LedgerError::InvalidInput("APDU too large"))?;
        if apdu.is_empty() {
            return Err(LedgerError::InvalidInput("empty APDU"));
        }
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < apdu.len() {
            let index = u16::try_from(frames.len())
                .map_err(|_| LedgerError::InvalidInput("too many frames"))?;
            let mut frame = vec![5];
            frame.extend_from_slice(&index.to_be_bytes());
            if index == 0 {
                frame.extend_from_slice(&length.to_be_bytes());
            }
            let end = (offset + mtu - frame.len()).min(apdu.len());
            frame.extend_from_slice(&apdu[offset..end]);
            frames.push(frame);
            offset = end;
        }
        Ok(frames)
    }
}

#[derive(Default)]
pub(crate) struct BleResponse {
    next: u16,
    length: Option<usize>,
    bytes: Vec<u8>,
}

impl BleResponse {
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, LedgerError> {
        if frame.len() < 3 || frame[0] != 5 || u16::from_be_bytes([frame[1], frame[2]]) != self.next
        {
            return Err(LedgerError::Protocol("invalid BLE tag or sequence"));
        }
        let header = if self.next == 0 {
            if frame.len() < 5 {
                return Err(LedgerError::Protocol("missing response length"));
            }
            let length = u16::from_be_bytes([frame[3], frame[4]]) as usize;
            if length < 2 {
                return Err(LedgerError::Protocol("response lacks status word"));
            }
            self.length = Some(length);
            5
        } else {
            3
        };
        let length = self
            .length
            .ok_or(LedgerError::Protocol("missing first frame"))?;
        if frame.len() <= header || self.bytes.len() + frame.len() - header > length {
            return Err(LedgerError::Protocol("invalid response payload length"));
        }
        self.bytes.extend_from_slice(&frame[header..]);
        self.next = self
            .next
            .checked_add(1)
            .ok_or(LedgerError::Protocol("sequence overflow"))?;
        Ok((self.bytes.len() == length).then(|| std::mem::take(&mut self.bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_match_wire_vectors_at_first_and_continuation_boundaries() {
        assert_eq!(
            BleFrames::encode(&[0xe0, 2, 0, 0, 1, 0], 8).unwrap(),
            vec![vec![5, 0, 0, 0, 6, 0xe0, 2, 0], vec![5, 0, 1, 0, 1, 0]]
        );
        let mut response = BleResponse::default();
        assert!(response.push(&[5, 0, 0, 0, 4, 0x12]).unwrap().is_none());
        assert_eq!(
            response.push(&[5, 0, 1, 0x34, 0x90, 0]).unwrap(),
            Some(vec![0x12, 0x34, 0x90, 0])
        );
    }

    #[test]
    fn malformed_frames_are_rejected_before_returning_a_response() {
        for frame in [
            vec![],
            vec![5, 0],
            vec![8, 0, 0, 0, 2, 0x90, 0],
            vec![5, 0, 1, 0x90, 0],
            vec![5, 0, 0, 0, 1, 0x90],
            vec![5, 0, 0, 0, 2, 0x90, 0, 0],
            vec![5, 0, 0, 0, 2],
        ] {
            assert!(BleResponse::default().push(&frame).is_err(), "{frame:?}");
        }
        let mut response = BleResponse::default();
        response.push(&[5, 0, 0, 0, 3, 0x12]).unwrap();
        assert!(response.push(&[5, 0, 0, 0x90, 0]).is_err());
        for mtu in [0, 5, 256] {
            assert!(BleFrames::encode(&[1], mtu).is_err());
        }
    }
}
