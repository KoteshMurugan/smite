//! BOLT 2 `tx_ack_rbf` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// TLV type for funding output contribution.
const TLV_FUNDING_OUTPUT_CONTRIBUTION: u64 = 0;

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 1;

/// BOLT 2 `tx_ack_rbf` message (type 73).
///
/// Sent by the non-initiator in response to `tx_init_rbf` to acknowledge
/// acceptance of a replace-by-fee (RBF) negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAckRbf {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Optional TLV extensions.
    pub tlvs: TxAckRbfTlvs,
}

/// TLV extensions for the `tx_ack_rbf` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxAckRbfTlvs {
    /// The amount the non-initiator will contribute to the funding output.
    /// Signed to allow negative (withdrawal) amounts.
    pub funding_output_contribution: Option<i64>,
    /// If set, the sender requires all inputs to be confirmed on-chain.
    pub require_confirmed_inputs: bool,
}

impl TxAckRbf {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(contribution) = self.tlvs.funding_output_contribution {
            let mut val = Vec::new();
            contribution.write(&mut val);
            tlv_stream.add(TLV_FUNDING_OUTPUT_CONTRIBUTION, val);
        }
        if self.tlvs.require_confirmed_inputs {
            tlv_stream.add(TLV_REQUIRE_CONFIRMED_INPUTS, vec![]);
        }
        out.extend(tlv_stream.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;

        let tlv_stream = TlvStream::decode_with_known(
            cursor,
            &[TLV_FUNDING_OUTPUT_CONTRIBUTION, TLV_REQUIRE_CONFIRMED_INPUTS],
        )?;

        let funding_output_contribution = tlv_stream
            .get(TLV_FUNDING_OUTPUT_CONTRIBUTION)
            .map(|mut v| i64::read(&mut v).expect("valid i64 in TLV"));

        let require_confirmed_inputs = tlv_stream.get(TLV_REQUIRE_CONFIRMED_INPUTS).is_some();

        Ok(Self {
            channel_id,
            tlvs: TxAckRbfTlvs { funding_output_contribution, require_confirmed_inputs },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxAckRbf {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs::default(),
        };
        assert_eq!(msg.encode().len(), CHANNEL_ID_SIZE);
    }

    #[test]
    fn roundtrip_no_tlvs() {
        let original = TxAckRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs::default(),
        };
        let decoded = TxAckRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_contribution() {
        let original = TxAckRbf {
            channel_id: ChannelId::new([0xcd; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs { funding_output_contribution: Some(50_000), require_confirmed_inputs: false },
        };
        let decoded = TxAckRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_negative_contribution() {
        let original = TxAckRbf {
            channel_id: ChannelId::new([0xef; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs { funding_output_contribution: Some(-1_000), require_confirmed_inputs: true },
        };
        let decoded = TxAckRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAckRbf::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAckRbf::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
