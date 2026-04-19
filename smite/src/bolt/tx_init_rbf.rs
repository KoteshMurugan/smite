//! BOLT 2 `tx_init_rbf` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// TLV type for funding output contribution.
const TLV_FUNDING_OUTPUT_CONTRIBUTION: u64 = 0;

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 1;

/// BOLT 2 `tx_init_rbf` message (type 72).
///
/// Sent by the channel initiator to begin a replace-by-fee (RBF) negotiation
/// for the funding transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInitRbf {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The locktime for the replacement funding transaction.
    pub locktime: u32,
    /// The feerate for the replacement transaction, in satoshis per 1000 weight units.
    pub feerate_per_kw: u32,
    /// Optional TLV extensions.
    pub tlvs: TxInitRbfTlvs,
}

/// TLV extensions for the `tx_init_rbf` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxInitRbfTlvs {
    /// The amount the initiator will contribute to the funding output.
    /// Signed to allow negative (withdrawal) amounts.
    pub funding_output_contribution: Option<i64>,
    /// If set, the sender requires all inputs to be confirmed on-chain.
    pub require_confirmed_inputs: bool,
}

impl TxInitRbf {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.locktime.write(&mut out);
        self.feerate_per_kw.write(&mut out);

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
        let locktime = u32::read(&mut cursor)?;
        let feerate_per_kw = u32::read(&mut cursor)?;

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
            locktime,
            feerate_per_kw,
            tlvs: TxInitRbfTlvs { funding_output_contribution, require_confirmed_inputs },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxInitRbf {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            locktime: 800_000,
            feerate_per_kw: 2_500,
            tlvs: TxInitRbfTlvs::default(),
        };
        // channel_id(32) + locktime(4) + feerate(4) = 40
        assert_eq!(msg.encode().len(), 40);
    }

    #[test]
    fn roundtrip_no_tlvs() {
        let original = TxInitRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            locktime: 700_000,
            feerate_per_kw: 1_500,
            tlvs: TxInitRbfTlvs::default(),
        };
        let decoded = TxInitRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_contribution() {
        let original = TxInitRbf {
            channel_id: ChannelId::new([0xcd; CHANNEL_ID_SIZE]),
            locktime: 800_100,
            feerate_per_kw: 3_000,
            tlvs: TxInitRbfTlvs { funding_output_contribution: Some(100_000), require_confirmed_inputs: false },
        };
        let decoded = TxInitRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_negative_contribution() {
        let original = TxInitRbf {
            channel_id: ChannelId::new([0xef; CHANNEL_ID_SIZE]),
            locktime: 0,
            feerate_per_kw: 5_000,
            tlvs: TxInitRbfTlvs { funding_output_contribution: Some(-500), require_confirmed_inputs: true },
        };
        let decoded = TxInitRbf::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxInitRbf::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxInitRbf::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
