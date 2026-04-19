//! BOLT 2 `tx_add_input` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_add_input` message (type 66).
///
/// Sent during interactive transaction construction to add an input to the
/// transaction being negotiated.  The serial ID must be even for the initiator
/// and odd for the non-initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAddInput {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// A unique serial ID for this input.  Must be even for initiator, odd for non-initiator.
    pub serial_id: u64,
    /// The previous transaction serialized in Bitcoin wire format.
    pub prevtx: Vec<u8>,
    /// The output index in the previous transaction.
    pub prevtx_vout: u32,
    /// The input sequence number.
    pub sequence: u32,
}

impl TxAddInput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        self.prevtx.write(&mut out);
        self.prevtx_vout.write(&mut out);
        self.sequence.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let serial_id = u64::read(&mut cursor)?;
        let prevtx = Vec::<u8>::read(&mut cursor)?;
        let prevtx_vout = u32::read(&mut cursor)?;
        let sequence = u32::read(&mut cursor)?;

        Ok(Self { channel_id, serial_id, prevtx, prevtx_vout, sequence })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxAddInput {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            serial_id: 0,
            prevtx: vec![0x01, 0x00, 0x00, 0x00],
            prevtx_vout: 0,
            sequence: 0xFFFFFFFD,
        };
        // channel_id(32) + serial_id(8) + prevtx_len(2) + prevtx(4) + vout(4) + sequence(4) = 54
        assert_eq!(msg.encode().len(), 54);
    }

    #[test]
    fn roundtrip() {
        let original = TxAddInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            prevtx: vec![0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb],
            prevtx_vout: 1,
            sequence: 0xFFFFFFFD,
        };
        let decoded = TxAddInput::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_prevtx() {
        let original = TxAddInput {
            channel_id: ChannelId::new([0xcd; CHANNEL_ID_SIZE]),
            serial_id: 1,
            prevtx: Vec::new(),
            prevtx_vout: 0,
            sequence: 0,
        };
        let decoded = TxAddInput::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAddInput::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_truncated_serial_id() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            TxAddInput::decode(&data),
            Err(BoltError::Truncated { expected: 8, actual: 4 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAddInput::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
