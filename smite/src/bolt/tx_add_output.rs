//! BOLT 2 `tx_add_output` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_add_output` message (type 67).
///
/// Sent during interactive transaction construction to add an output to the
/// transaction being negotiated.  The serial ID must be even for the initiator
/// and odd for the non-initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAddOutput {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// A unique serial ID for this output.  Must be even for initiator, odd for non-initiator.
    pub serial_id: u64,
    /// The satoshi amount for this output.
    pub sats: u64,
    /// The scriptPubKey for this output.
    pub script: Vec<u8>,
}

impl TxAddOutput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        self.sats.write(&mut out);
        self.script.write(&mut out);
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
        let sats = u64::read(&mut cursor)?;
        let script = Vec::<u8>::read(&mut cursor)?;

        Ok(Self { channel_id, serial_id, sats, script })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxAddOutput {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            serial_id: 0,
            sats: 100_000,
            script: vec![0x00, 0x14],
        };
        // channel_id(32) + serial_id(8) + sats(8) + script_len(2) + script(2) = 52
        assert_eq!(msg.encode().len(), 52);
    }

    #[test]
    fn roundtrip() {
        let original = TxAddOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            sats: 50_000,
            script: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc],
        };
        let decoded = TxAddOutput::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_script() {
        let original = TxAddOutput {
            channel_id: ChannelId::new([0xcd; CHANNEL_ID_SIZE]),
            serial_id: 1,
            sats: 0,
            script: Vec::new(),
        };
        let decoded = TxAddOutput::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAddOutput::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
