//! BOLT 2 `closing_signed` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;
use secp256k1::ecdsa::Signature;

const TLV_FEE_RANGE: u64 = 1;

/// BOLT 2 `closing_signed` message (type 39).
///
/// Sent by both peers after `shutdown` to negotiate the final closing fee.
/// Each side proposes a `fee_satoshis` and signs the close transaction at
/// that fee; convergence happens when both sides agree on a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingSigned {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The proposed fee for the close transaction, in satoshis.
    pub fee_satoshis: u64,
    /// Signature over the close transaction at this fee.
    pub signature: Signature,
    /// Optional TLV extensions.
    pub tlvs: ClosingSignedTlvs,
}

/// TLV extensions for the `closing_signed` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosingSignedTlvs {
    /// Sender's acceptable fee range for one-shot agreement.
    pub fee_range: Option<FeeRange>,
}

/// Acceptable fee range carried in TLV 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRange {
    /// Minimum fee the sender will accept.
    pub min_fee_satoshis: u64,
    /// Maximum fee the sender will accept.
    pub max_fee_satoshis: u64,
}

impl ClosingSigned {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.fee_satoshis.write(&mut out);
        self.signature.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(range) = self.tlvs.fee_range {
            let mut val = Vec::new();
            range.min_fee_satoshis.write(&mut val);
            range.max_fee_satoshis.write(&mut val);
            tlv_stream.add(TLV_FEE_RANGE, val);
        }
        out.extend(tlv_stream.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short or `InvalidSignature`
    /// if the signature bytes are not a valid compact ECDSA signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let fee_satoshis = u64::read(&mut cursor)?;
        let signature = Signature::read(&mut cursor)?;

        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_FEE_RANGE])?;
        let fee_range = tlv_stream.get(TLV_FEE_RANGE).and_then(|mut v| {
            let min_fee_satoshis = u64::read(&mut v).ok()?;
            let max_fee_satoshis = u64::read(&mut v).ok()?;
            Some(FeeRange {
                min_fee_satoshis,
                max_fee_satoshis,
            })
        });

        Ok(Self {
            channel_id,
            fee_satoshis,
            signature,
            tlvs: ClosingSignedTlvs { fee_range },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use secp256k1::{Message, Secp256k1, SecretKey};

    fn sample_signature() -> Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x22; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        secp.sign_ecdsa(msg, &sk)
    }

    fn sample() -> ClosingSigned {
        ClosingSigned {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            fee_satoshis: 1_500,
            signature: sample_signature(),
            tlvs: ClosingSignedTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        // channel_id(32) + fee_satoshis(8) + signature(64) = 104
        assert_eq!(sample().encode().len(), 104);
    }

    #[test]
    fn roundtrip_no_tlvs() {
        let original = sample();
        let decoded = ClosingSigned::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_fee_range() {
        let mut original = sample();
        original.tlvs.fee_range = Some(FeeRange {
            min_fee_satoshis: 1_000,
            max_fee_satoshis: 5_000,
        });
        let decoded = ClosingSigned::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ClosingSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            ClosingSigned::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0,
            })
        );
    }
}
