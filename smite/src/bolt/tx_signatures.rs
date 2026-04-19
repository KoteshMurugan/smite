//! BOLT 2 `tx_signatures` message.

use super::BoltError;
use super::types::{ChannelId, Txid};
use super::wire::WireFormat;

/// A witness stack item list for one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// The witness stack items (signatures, pubkeys, scripts, etc.).
    pub items: Vec<Vec<u8>>,
}

/// Encode a Bitcoin compact-size varint.
fn encode_compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u64::from(u32::MAX) {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Decode a Bitcoin compact-size varint, returning (value, bytes_consumed).
fn decode_compact_size(bytes: &[u8]) -> Result<(u64, usize), BoltError> {
    if bytes.is_empty() {
        return Err(BoltError::Truncated { expected: 1, actual: 0 });
    }
    match bytes[0] {
        b @ 0x00..=0xfc => Ok((u64::from(b), 1)),
        0xfd => {
            if bytes.len() < 3 {
                return Err(BoltError::Truncated { expected: 3, actual: bytes.len() });
            }
            Ok((u64::from(u16::from_le_bytes([bytes[1], bytes[2]])), 3))
        }
        0xfe => {
            if bytes.len() < 5 {
                return Err(BoltError::Truncated { expected: 5, actual: bytes.len() });
            }
            Ok((
                u64::from(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])),
                5,
            ))
        }
        0xff => {
            if bytes.len() < 9 {
                return Err(BoltError::Truncated { expected: 9, actual: bytes.len() });
            }
            Ok((
                u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]),
                9,
            ))
        }
    }
}

impl Witness {
    /// Serialize one witness as `u16 len || witness_stack` where `witness_stack`
    /// is the standard Bitcoin segwit format: `varint(num_items) ||
    /// (varint(item_len) || item_bytes)*` per BOLT 2 `witness_element`.
    fn encode(&self) -> Vec<u8> {
        let mut stack = Vec::new();
        encode_compact_size(self.items.len() as u64, &mut stack);
        for item in &self.items {
            encode_compact_size(item.len() as u64, &mut stack);
            stack.extend_from_slice(item);
        }
        let mut out = Vec::with_capacity(2 + stack.len());
        (stack.len() as u16).write(&mut out);
        out.extend_from_slice(&stack);
        out
    }

    fn decode(cursor: &mut &[u8]) -> Result<Self, BoltError> {
        let stack_len = u16::read(cursor)? as usize;
        if cursor.len() < stack_len {
            return Err(BoltError::Truncated { expected: stack_len, actual: cursor.len() });
        }
        let mut stack = &cursor[..stack_len];
        *cursor = &cursor[stack_len..];

        let (num_items, consumed) = decode_compact_size(stack)?;
        stack = &stack[consumed..];
        let mut items = Vec::with_capacity(num_items as usize);
        for _ in 0..num_items {
            let (item_len, consumed) = decode_compact_size(stack)?;
            stack = &stack[consumed..];
            let item_len = item_len as usize;
            if stack.len() < item_len {
                return Err(BoltError::Truncated { expected: item_len, actual: stack.len() });
            }
            items.push(stack[..item_len].to_vec());
            stack = &stack[item_len..];
        }
        Ok(Self { items })
    }
}

/// BOLT 2 `tx_signatures` message (type 71).
///
/// Sent after both peers have exchanged `tx_complete` to provide witnesses
/// for each input in the negotiated transaction.  The peer whose `txid` is
/// lexicographically smaller sends signatures first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSignatures {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The transaction ID being signed.
    pub txid: Txid,
    /// Witnesses for each input, in input order.
    pub witnesses: Vec<Witness>,
}

impl TxSignatures {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.txid.write(&mut out);
        (self.witnesses.len() as u16).write(&mut out);
        for witness in &self.witnesses {
            out.extend(witness.encode());
        }
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
        let txid = Txid::read(&mut cursor)?;
        let num_witnesses = u16::read(&mut cursor)? as usize;
        let mut witnesses = Vec::with_capacity(num_witnesses);
        for _ in 0..num_witnesses {
            witnesses.push(Witness::decode(&mut cursor)?);
        }
        Ok(Self { channel_id, txid, witnesses })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, TXID_SIZE};
    use super::*;
    use secp256k1::hashes::Hash;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxSignatures {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            txid: Txid::from_byte_array([0xab; TXID_SIZE]),
            witnesses: vec![],
        };
        // channel_id(32) + txid(32) + num_witnesses(2) = 66
        assert_eq!(msg.encode().len(), 66);
    }

    #[test]
    fn roundtrip_no_witnesses() {
        let original = TxSignatures {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            txid: Txid::from_byte_array([0xcd; TXID_SIZE]),
            witnesses: vec![],
        };
        let decoded = TxSignatures::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_witnesses() {
        let original = TxSignatures {
            channel_id: ChannelId::new([0x22; CHANNEL_ID_SIZE]),
            txid: Txid::from_byte_array([0x33; TXID_SIZE]),
            witnesses: vec![
                Witness { items: vec![vec![0xFF; 72], vec![0xAA; 33]] },
                Witness { items: vec![vec![0xBB; 71]] },
                Witness { items: vec![] },
            ],
        };
        let decoded = TxSignatures::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxSignatures::decode(&[0x00; 20]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 20 })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxSignatures::decode(&[]),
            Err(BoltError::Truncated { expected: CHANNEL_ID_SIZE, actual: 0 })
        );
    }
}
