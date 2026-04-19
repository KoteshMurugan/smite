//! BOLT 2 `commitment_signed` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `commitment_signed` message (type 132).
///
/// Sent to commit to the current set of HTLCs and balance. Carries the peer's
/// signature for the counterparty's commitment transaction plus per-HTLC
/// signatures. We carry the signature payload as raw bytes so a scenario can
/// emit fuzz-friendly garbage without going through ECDSA validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSigned {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Raw payload following the channel id (signature + num_htlcs + htlc sigs).
    pub payload: Vec<u8>,
}

impl CommitmentSigned {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.payload.len());
        self.channel_id.write(&mut out);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for the channel id.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        Ok(Self {
            channel_id,
            payload: cursor.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn roundtrip() {
        let msg = CommitmentSigned {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            payload: vec![0x01, 0x02, 0x03, 0x04],
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 4);
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            CommitmentSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20,
            })
        );
    }
}
