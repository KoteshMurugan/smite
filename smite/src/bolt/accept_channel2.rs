//! BOLT 2 `accept_channel2` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;
use secp256k1::PublicKey;

/// TLV type for upfront shutdown script.
const TLV_UPFRONT_SHUTDOWN_SCRIPT: u64 = 0;

/// TLV type for channel type.
const TLV_CHANNEL_TYPE: u64 = 1;

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 2;

/// BOLT 2 `accept_channel2` message (type 65).
///
/// Sent by the non-initiator in response to `open_channel2` to accept the
/// v2 channel establishment and contribute their own funds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptChannel2 {
    /// A temporary channel ID used until the funding outpoint is announced.
    pub temporary_channel_id: ChannelId,
    /// The amount the channel non-initiator contributes to the channel, in satoshis.
    pub funding_satoshis: u64,
    /// The threshold below which outputs on transactions broadcast by the non-initiator will be omitted.
    pub dust_limit_satoshis: u64,
    /// The maximum total value of inbound HTLCs in flight, in millisatoshis.
    pub max_htlc_value_in_flight_msat: u64,
    /// The minimum HTLC value the non-initiator will accept, in millisatoshis.
    pub htlc_minimum_msat: u64,
    /// The minimum number of blocks the initiator must wait to claim on-chain funds.
    pub minimum_depth: u32,
    /// The number of blocks the counterparty must wait to claim on-chain funds.
    pub to_self_delay: u16,
    /// The maximum number of inbound HTLCs toward the non-initiator.
    pub max_accepted_htlcs: u16,
    /// The non-initiator's public key for the funding transaction.
    pub funding_pubkey: PublicKey,
    /// The basepoint used to derive revocation keys.
    pub revocation_basepoint: PublicKey,
    /// The basepoint used to derive payment keys.
    pub payment_basepoint: PublicKey,
    /// The basepoint used to derive delayed payment keys.
    pub delayed_payment_basepoint: PublicKey,
    /// The basepoint used to derive HTLC keys.
    pub htlc_basepoint: PublicKey,
    /// The first per-commitment point.
    pub first_per_commitment_point: PublicKey,
    /// The second per-commitment point.
    pub second_per_commitment_point: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: AcceptChannel2Tlvs,
}

/// TLV extensions for the `accept_channel2` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptChannel2Tlvs {
    /// Optionally specifies the scriptPubKey for cooperative close.
    pub upfront_shutdown_script: Option<Vec<u8>>,
    /// The channel type represented as feature bits.
    pub channel_type: Option<Vec<u8>>,
    /// If set, the sender requires the receiver to only use confirmed inputs.
    pub require_confirmed_inputs: bool,
}

impl AcceptChannel2 {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.temporary_channel_id.write(&mut out);
        self.funding_satoshis.write(&mut out);
        self.dust_limit_satoshis.write(&mut out);
        self.max_htlc_value_in_flight_msat.write(&mut out);
        self.htlc_minimum_msat.write(&mut out);
        self.minimum_depth.write(&mut out);
        self.to_self_delay.write(&mut out);
        self.max_accepted_htlcs.write(&mut out);
        self.funding_pubkey.write(&mut out);
        self.revocation_basepoint.write(&mut out);
        self.payment_basepoint.write(&mut out);
        self.delayed_payment_basepoint.write(&mut out);
        self.htlc_basepoint.write(&mut out);
        self.first_per_commitment_point.write(&mut out);
        self.second_per_commitment_point.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(script) = &self.tlvs.upfront_shutdown_script {
            tlv_stream.add(TLV_UPFRONT_SHUTDOWN_SCRIPT, script.clone());
        }
        if let Some(channel_type) = &self.tlvs.channel_type {
            tlv_stream.add(TLV_CHANNEL_TYPE, channel_type.clone());
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
    /// Returns `Truncated` if the payload is too short or `InvalidPublicKey` if any pubkey is invalid.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let temporary_channel_id = WireFormat::read(&mut cursor)?;
        let funding_satoshis = WireFormat::read(&mut cursor)?;
        let dust_limit_satoshis = WireFormat::read(&mut cursor)?;
        let max_htlc_value_in_flight_msat = WireFormat::read(&mut cursor)?;
        let htlc_minimum_msat = WireFormat::read(&mut cursor)?;
        let minimum_depth = WireFormat::read(&mut cursor)?;
        let to_self_delay = WireFormat::read(&mut cursor)?;
        let max_accepted_htlcs = WireFormat::read(&mut cursor)?;
        let funding_pubkey = WireFormat::read(&mut cursor)?;
        let revocation_basepoint = WireFormat::read(&mut cursor)?;
        let payment_basepoint = WireFormat::read(&mut cursor)?;
        let delayed_payment_basepoint = WireFormat::read(&mut cursor)?;
        let htlc_basepoint = WireFormat::read(&mut cursor)?;
        let first_per_commitment_point = WireFormat::read(&mut cursor)?;
        let second_per_commitment_point = WireFormat::read(&mut cursor)?;

        let tlv_stream = TlvStream::decode_with_known(
            cursor,
            &[TLV_UPFRONT_SHUTDOWN_SCRIPT, TLV_REQUIRE_CONFIRMED_INPUTS],
        )?;

        let upfront_shutdown_script = tlv_stream.get(TLV_UPFRONT_SHUTDOWN_SCRIPT).map(Vec::from);
        let channel_type = tlv_stream.get(TLV_CHANNEL_TYPE).map(Vec::from);
        let require_confirmed_inputs = tlv_stream.get(TLV_REQUIRE_CONFIRMED_INPUTS).is_some();

        Ok(Self {
            temporary_channel_id,
            funding_satoshis,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            htlc_minimum_msat,
            minimum_depth,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            second_per_commitment_point,
            tlvs: AcceptChannel2Tlvs {
                upfront_shutdown_script,
                channel_type,
                require_confirmed_inputs,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn dummy_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn sample() -> AcceptChannel2 {
        let pk = dummy_pubkey();
        AcceptChannel2 {
            temporary_channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            funding_satoshis: 100_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 150_000_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 3,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            second_per_commitment_point: pk,
            tlvs: AcceptChannel2Tlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let encoded = sample().encode();
        // channel_id(32) + 4×u64(32) + u32(4) + 2×u16(4) + 7×pubkey(231) = 303
        assert_eq!(encoded.len(), 303);
    }

    #[test]
    fn roundtrip_no_tlvs() {
        let original = sample();
        let decoded = AcceptChannel2::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let mut original = sample();
        original.tlvs = AcceptChannel2Tlvs {
            upfront_shutdown_script: Some(vec![0x00, 0x14]),
            channel_type: Some(vec![0x01, 0x00]),
            require_confirmed_inputs: true,
        };
        let decoded = AcceptChannel2::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            AcceptChannel2::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            AcceptChannel2::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
