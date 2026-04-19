//! BOLT 1 `channel_reestablish` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;
use secp256k1::PublicKey;

/// BOLT 1 `channel_reestablish` message (type 136).
///
/// Sent by both peers after reconnecting to re-synchronize channel state.
/// In the dual-funding context this drives `handle_peer_reestablish` in
/// `dualopend.c` and the equivalent in `closingd.c`.
///
/// Wire layout (fixed fields, 113 bytes):
/// ```text
/// [32: channel_id]
/// [ 8: next_commitment_number]   (u64 big-endian)
/// [ 8: next_revocation_number]   (u64 big-endian)
/// [32: your_last_per_commitment_secret]
/// [33: my_current_per_commitment_point]
/// ```
/// Followed by optional TLVs (e.g., `next_funding`, TLV type 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReestablish {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Commitment number of the *next* commitment transaction the sender
    /// expects to receive.  For a channel that has received the initial
    /// commitment tx (number 0), this is 1.  Zero means "no commitment
    /// received yet".
    pub next_commitment_number: u64,
    /// Remote revocation number the sender expects next.  Zero for a channel
    /// that has not yet revoked any commitment transaction.
    pub next_revocation_number: u64,
    /// The per-commitment secret for the previous revoked commitment.
    /// Must be all-zeros when `next_revocation_number == 0` (no revocations
    /// have been issued yet).
    pub your_last_per_commitment_secret: [u8; 32],
    /// The sender's current per-commitment point (compressed secp256k1 public
    /// key).  Matches `first_per_commitment_point` from `open_channel2` /
    /// `accept_channel2` for a fresh channel.
    pub my_current_per_commitment_point: PublicKey,
}

impl ChannelReestablish {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.next_commitment_number.write(&mut out);
        self.next_revocation_number.write(&mut out);
        self.your_last_per_commitment_secret.write(&mut out);
        self.my_current_per_commitment_point.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short, or `InvalidPublicKey`
    /// if the per-commitment point bytes are not a valid compressed point.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let next_commitment_number = u64::read(&mut cursor)?;
        let next_revocation_number = u64::read(&mut cursor)?;
        let your_last_per_commitment_secret: [u8; 32] = WireFormat::read(&mut cursor)?;
        let my_current_per_commitment_point = PublicKey::read(&mut cursor)?;
        // Remaining bytes are optional TLVs — ignore unknown entries per BOLT 1.
        Ok(Self {
            channel_id,
            next_commitment_number,
            next_revocation_number,
            your_last_per_commitment_secret,
            my_current_per_commitment_point,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn sample_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([0x11; 32]).expect("valid secret");
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn sample() -> ChannelReestablish {
        ChannelReestablish {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            next_commitment_number: 1,
            next_revocation_number: 0,
            your_last_per_commitment_secret: [0u8; 32],
            my_current_per_commitment_point: sample_pubkey(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        // channel_id(32) + next_commitment_number(8) + next_revocation_number(8)
        // + your_last_per_commitment_secret(32) + my_current_per_commitment_point(33) = 113
        assert_eq!(sample().encode().len(), 113);
    }

    #[test]
    fn roundtrip() {
        let original = sample();
        let decoded = ChannelReestablish::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ChannelReestablish::decode(&[0u8; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            ChannelReestablish::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }

    #[test]
    fn decode_truncated_at_point() {
        // 32 + 8 + 8 + 32 = 80 bytes — missing the 33-byte pubkey
        assert_eq!(
            ChannelReestablish::decode(&[0u8; 80]),
            Err(BoltError::Truncated { expected: 33, actual: 0 })
        );
    }
}
