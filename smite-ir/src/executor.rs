//! IR program executor.
//!
//! Executes a [`Program`] against a live [`NoiseConnection`], driving the
//! BOLT 2 interactive-tx protocol on behalf of the fuzzer.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{
    AcceptChannel2, ChannelReestablish, ClosingSigned, ClosingSignedTlvs, CommitmentSigned,
    Message, OpenChannel, OpenChannel2, OpenChannel2Tlvs, OpenChannelTlvs, Shutdown, TxAckRbf,
    TxAckRbfTlvs, TxAddInput, TxAddOutput, TxComplete, TxInitRbf, TxInitRbfTlvs, TxRemoveInput,
    TxRemoveOutput, TxSignatures, Witness,
};
use smite::noise::NoiseConnection;

use crate::context::ProgramContext;
use crate::operation::{AcceptChannel2Field, AcceptChannelField, Operation};
use crate::program::Program;
use crate::variable::{Variable, VariableType};

/// Error returned when a program instruction fails to execute.
#[derive(Debug)]
pub enum ExecutorError {
    /// The connection was closed or a send/recv failed.
    Connection(smite::noise::ConnectionError),
    /// Received an unexpected BOLT message type.
    UnexpectedMessage { expected: &'static str, got: u16 },
    /// Failed to decode a received BOLT message.
    Decode(smite::bolt::BoltError),
    /// A variable referenced by an instruction was void (produced no value).
    VoidVariable(usize),
    /// A variable had the wrong type for the operation.
    TypeMismatch { index: usize, expected: VariableType },
    /// An instruction had the wrong number of inputs (AFL++ mutation artifact).
    WrongInputCount { expected: usize, got: usize },
}

impl From<smite::noise::ConnectionError> for ExecutorError {
    fn from(e: smite::noise::ConnectionError) -> Self {
        Self::Connection(e)
    }
}

impl From<smite::bolt::BoltError> for ExecutorError {
    fn from(e: smite::bolt::BoltError) -> Self {
        Self::Decode(e)
    }
}

// ── Interactive-tx state tracking ─────────────────────────────────────────────

/// An input tracked during interactive-tx negotiation.
#[derive(Clone)]
struct ItxInput {
    /// Serial ID (BOLT 2 ordering: lower serial_id = first in negotiated tx).
    serial_id: u64,
    /// txid of the previous transaction being spent (internal byte order).
    txid: [u8; 32],
    /// Output index in the previous transaction.
    vout: u32,
    /// Input sequence number.
    sequence: u32,
    /// Signing info — Some for our inputs, None for CLN's inputs.
    signing: Option<ItxSigningInfo>,
}

/// BIP 143 signing info for a P2WPKH input we control.
#[derive(Clone)]
struct ItxSigningInfo {
    /// UTXO value in satoshis (needed for BIP 143 sighash).
    amount_sats: u64,
    /// Compressed public key (33 bytes).
    pubkey: [u8; 33],
    /// Private key (32 bytes).
    privkey: [u8; 32],
}

/// An output tracked during interactive-tx negotiation.
#[derive(Clone)]
struct ItxOutput {
    /// Serial ID (BOLT 2 ordering).
    serial_id: u64,
    /// Output value in satoshis.
    sats: u64,
    /// scriptPubKey.
    script: Vec<u8>,
}

// ── Bitcoin transaction utilities ──────────────────────────────────────────────

/// Read a Bitcoin script or byte vector encoded as `varint_len || bytes`.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    if bytes.is_empty() {
        return None;
    }
    match bytes[0] {
        b @ 0x00..=0xfc => Some((u64::from(b), 1)),
        0xfd => {
            if bytes.len() < 3 {
                return None;
            }
            Some((u64::from(u16::from_le_bytes([bytes[1], bytes[2]])), 3))
        }
        0xfe => {
            if bytes.len() < 5 {
                return None;
            }
            Some((
                u64::from(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])),
                5,
            ))
        }
        0xff => {
            if bytes.len() < 9 {
                return None;
            }
            Some((
                u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]),
                9,
            ))
        }
    }
}

/// Encode a u64 as a Bitcoin varint.
fn encode_varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// Compute the Bitcoin txid (SHA256d) of a raw transaction.
///
/// Handles both segwit (strips witness) and non-segwit transactions.
/// Returns `None` if the raw bytes cannot be parsed.
fn btc_txid(raw_tx: &[u8]) -> Option<[u8; 32]> {
    use secp256k1::hashes::{sha256d, Hash};

    // Segwit: version(4) + marker(0x00) + flag(0x01) + ...
    let non_segwit = if raw_tx.len() > 5 && raw_tx[4] == 0x00 && raw_tx[5] == 0x01 {
        strip_segwit_witness(raw_tx)?
    } else {
        raw_tx.to_vec()
    };

    let hash = sha256d::Hash::hash(&non_segwit);
    Some(*hash.as_byte_array())
}

/// Strip segwit marker, flag, and witness data from a raw Bitcoin transaction,
/// returning the non-segwit serialization used for txid computation.
fn strip_segwit_witness(raw_tx: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw_tx.len());

    // version (4 bytes)
    if raw_tx.len() < 6 {
        return None;
    }
    out.extend_from_slice(&raw_tx[..4]);

    // skip marker (byte 4 = 0x00) and flag (byte 5 = 0x01)
    let mut cursor: &[u8] = &raw_tx[6..];

    // input count
    let (in_count, in_count_len) = read_varint(cursor)?;
    out.extend_from_slice(&cursor[..in_count_len]);
    cursor = &cursor[in_count_len..];

    for _ in 0..in_count {
        // prevhash (32) + prevout (4)
        if cursor.len() < 36 {
            return None;
        }
        out.extend_from_slice(&cursor[..36]);
        cursor = &cursor[36..];

        // scriptSig: varint len + bytes
        let (script_len, script_len_sz) = read_varint(cursor)?;
        let total = script_len_sz + script_len as usize;
        if cursor.len() < total {
            return None;
        }
        out.extend_from_slice(&cursor[..total]);
        cursor = &cursor[total..];

        // sequence (4 bytes)
        if cursor.len() < 4 {
            return None;
        }
        out.extend_from_slice(&cursor[..4]);
        cursor = &cursor[4..];
    }

    // output count
    let (out_count, out_count_len) = read_varint(cursor)?;
    out.extend_from_slice(&cursor[..out_count_len]);
    cursor = &cursor[out_count_len..];

    for _ in 0..out_count {
        // value (8 bytes)
        if cursor.len() < 8 {
            return None;
        }
        out.extend_from_slice(&cursor[..8]);
        cursor = &cursor[8..];

        // scriptPubKey: varint len + bytes
        let (script_len, script_len_sz) = read_varint(cursor)?;
        let total = script_len_sz + script_len as usize;
        if cursor.len() < total {
            return None;
        }
        out.extend_from_slice(&cursor[..total]);
        cursor = &cursor[total..];
    }

    // skip witness data: for each input, (wit_count × (item_len + item_bytes))
    for _ in 0..in_count {
        let (wit_count, wit_count_sz) = read_varint(cursor)?;
        cursor = &cursor[wit_count_sz..];
        for _ in 0..wit_count {
            let (item_len, item_len_sz) = read_varint(cursor)?;
            let total = item_len_sz + item_len as usize;
            if cursor.len() < total {
                return None;
            }
            cursor = &cursor[total..];
        }
    }

    // locktime (4 bytes)
    if cursor.len() < 4 {
        return None;
    }
    out.extend_from_slice(&cursor[..4]);

    Some(out)
}

/// Build the BIP 143 P2WPKH scriptCode for `pubkey`.
///
/// Format (BOLT 2 / BIP 143):
///   `OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG`
///
/// The prefix `0x19` (= 25, the length) is prepended as required by BIP 143.
fn p2wpkh_script_code(pubkey: &[u8; 33]) -> Vec<u8> {
    use secp256k1::hashes::{ripemd160, sha256, Hash};
    let sha = sha256::Hash::hash(pubkey);
    let hash160 = ripemd160::Hash::hash(sha.as_byte_array());

    // scriptCode = 0x19 || OP_DUP OP_HASH160 OP_PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    let mut sc = vec![0x19u8, 0x76, 0xa9, 0x14];
    sc.extend_from_slice(hash160.as_byte_array());
    sc.extend_from_slice(&[0x88, 0xac]);
    sc
}

/// Compute the BIP 143 P2WPKH sighash for one input.
///
/// - `all_inputs` / `all_outputs`: ALL inputs/outputs in serial_id order.
/// - `signing_idx`: index into `all_inputs` of the input being signed.
/// - `amount_sats`: value of the UTXO being spent.
/// - `pubkey`: the P2WPKH pubkey.
/// - `locktime`: the funding transaction locktime.
fn bip143_p2wpkh_sighash(
    all_inputs: &[ItxInput],
    all_outputs: &[ItxOutput],
    signing_idx: usize,
    amount_sats: u64,
    pubkey: &[u8; 33],
    locktime: u32,
) -> [u8; 32] {
    use secp256k1::hashes::{sha256d, Hash};

    const SIGHASH_ALL: u32 = 1;
    const VERSION: u32 = 2;

    // hashPrevouts: SHA256d of all (txid || vout) concatenated
    let mut prevouts = Vec::new();
    for inp in all_inputs {
        prevouts.extend_from_slice(&inp.txid);
        prevouts.extend_from_slice(&inp.vout.to_le_bytes());
    }
    let hash_prevouts = sha256d::Hash::hash(&prevouts);

    // hashSequence: SHA256d of all sequences concatenated
    let mut seqs = Vec::new();
    for inp in all_inputs {
        seqs.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    let hash_sequence = sha256d::Hash::hash(&seqs);

    // hashOutputs: SHA256d of all (value || varint_script_len || script)
    let mut outputs_buf = Vec::new();
    for out in all_outputs {
        outputs_buf.extend_from_slice(&out.sats.to_le_bytes());
        outputs_buf.extend(encode_varint(out.script.len() as u64));
        outputs_buf.extend_from_slice(&out.script);
    }
    let hash_outputs = sha256d::Hash::hash(&outputs_buf);

    let inp = &all_inputs[signing_idx];
    let script_code = p2wpkh_script_code(pubkey);

    // BIP 143 preimage
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&VERSION.to_le_bytes());           // nVersion
    preimage.extend_from_slice(hash_prevouts.as_byte_array());    // hashPrevouts
    preimage.extend_from_slice(hash_sequence.as_byte_array());    // hashSequence
    preimage.extend_from_slice(&inp.txid);                        // outpoint txid
    preimage.extend_from_slice(&inp.vout.to_le_bytes());          // outpoint vout
    preimage.extend_from_slice(&script_code);                     // scriptCode
    preimage.extend_from_slice(&amount_sats.to_le_bytes());       // value
    preimage.extend_from_slice(&inp.sequence.to_le_bytes());      // nSequence
    preimage.extend_from_slice(hash_outputs.as_byte_array());     // hashOutputs
    preimage.extend_from_slice(&locktime.to_le_bytes());          // nLocktime
    preimage.extend_from_slice(&SIGHASH_ALL.to_le_bytes());       // sighash type

    let hash = sha256d::Hash::hash(&preimage);
    *hash.as_byte_array()
}

/// Serialize the funding transaction (no witness) and compute its txid as
/// double-SHA256, returning the bytes in *internal* (little-endian) byte
/// order.  Inputs/outputs are assumed pre-sorted by serial_id (BOLT 2).
fn compute_funding_txid(
    sorted_inputs: &[ItxInput],
    sorted_outputs: &[ItxOutput],
    locktime: u32,
) -> [u8; 32] {
    use secp256k1::hashes::{Hash, sha256d};

    let mut buf = Vec::with_capacity(256);
    // version = 2
    buf.extend_from_slice(&2i32.to_le_bytes());
    // input count varint
    buf.extend(encode_varint(sorted_inputs.len() as u64));
    for inp in sorted_inputs {
        buf.extend_from_slice(&inp.txid);
        buf.extend_from_slice(&inp.vout.to_le_bytes());
        buf.push(0x00); // empty scriptSig
        buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    // output count varint
    buf.extend(encode_varint(sorted_outputs.len() as u64));
    for out in sorted_outputs {
        buf.extend_from_slice(&out.sats.to_le_bytes());
        buf.extend(encode_varint(out.script.len() as u64));
        buf.extend_from_slice(&out.script);
    }
    buf.extend_from_slice(&locktime.to_le_bytes());

    sha256d::Hash::hash(&buf).to_byte_array()
}

/// Encode a single witness stack into Bitcoin wire format used inside a
/// witness_element: varint(num_items) + (varint(item_len) + item_bytes)*
fn encode_witness_stack(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(encode_varint(items.len() as u64));
    for item in items {
        out.extend(encode_varint(item.len() as u64));
        out.extend_from_slice(item);
    }
    out
}

/// Encode a Vec<Witness> into the BOLT 2 wire format for tx_signatures:
///   num_witnesses (u16) + for each: u16 len + raw witness bytes
/// where raw witness bytes = varint(num_items) + (varint(item_len) + bytes)*
fn encode_witnesses(witnesses: &[Witness]) -> Vec<u8> {
    let mut out = Vec::new();
    let n = witnesses.len() as u16;
    out.extend_from_slice(&n.to_be_bytes());
    for w in witnesses {
        let stack = encode_witness_stack(&w.items);
        let len = stack.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&stack);
    }
    out
}

/// Decode wire-encoded witnesses (BOLT 2 tx_signatures format).
fn decode_witnesses(bytes: &[u8]) -> Vec<Witness> {
    let mut cursor = bytes;

    let num_w = if cursor.len() >= 2 {
        let n = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        n
    } else {
        return vec![];
    };

    let mut witnesses = Vec::with_capacity(num_w);
    for _ in 0..num_w {
        if cursor.len() < 2 {
            break;
        }
        let len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        cursor = &cursor[2..];
        if cursor.len() < len {
            break;
        }
        let mut stack = &cursor[..len];
        cursor = &cursor[len..];

        let Some((num_items, consumed)) = read_varint(stack) else { break };
        stack = &stack[consumed..];
        let mut items = Vec::with_capacity(num_items as usize);
        for _ in 0..num_items {
            let Some((item_len, consumed)) = read_varint(stack) else { break };
            stack = &stack[consumed..];
            let item_len = item_len as usize;
            if stack.len() < item_len {
                break;
            }
            items.push(stack[..item_len].to_vec());
            stack = &stack[item_len..];
        }
        witnesses.push(Witness { items });
    }
    witnesses
}

// ── Executor ───────────────────────────────────────────────────────────────────

/// Executes an IR program against a live Lightning connection.
pub struct Executor<'a> {
    conn: &'a mut NoiseConnection,
    ctx: &'a ProgramContext,
    /// One entry per instruction in SSA order; `None` for void operations.
    vars: Vec<Option<Variable>>,

    // ── Interactive-tx mutable state ─────────────────────────────────────────
    /// All inputs added to the negotiated funding tx (ours + CLN's).
    itx_inputs: Vec<ItxInput>,
    /// All outputs added to the negotiated funding tx (ours + CLN's).
    itx_outputs: Vec<ItxOutput>,
    /// Locktime of the funding transaction, taken from open_channel2.locktime.
    itx_locktime: u32,
}

impl<'a> Executor<'a> {
    /// Create a new executor.
    pub fn new(conn: &'a mut NoiseConnection, ctx: &'a ProgramContext) -> Self {
        Self {
            conn,
            ctx,
            vars: Vec::new(),
            itx_inputs: Vec::new(),
            itx_outputs: Vec::new(),
            itx_locktime: 0,
        }
    }

    /// Execute a program, driving the protocol interaction.
    ///
    /// # Errors
    ///
    /// Returns an error if any instruction fails (connection closed, unexpected
    /// message, type mismatch, etc.).
    pub fn run(&mut self, program: &Program) -> Result<(), ExecutorError> {
        for instr in &program.instructions {
            let result = self.execute_op(&instr.operation, &instr.inputs)?;
            self.vars.push(result);
        }
        Ok(())
    }

    // -- Helpers to extract typed values from the variable store --

    fn get_var(&self, idx: usize) -> Result<&Variable, ExecutorError> {
        self.vars
            .get(idx)
            .and_then(Option::as_ref)
            .ok_or(ExecutorError::VoidVariable(idx))
    }

    fn get_chain_hash(&self, idx: usize) -> Result<[u8; 32], ExecutorError> {
        match self.get_var(idx)? {
            Variable::ChainHash(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::ChainHash }),
        }
    }

    fn get_channel_id(&self, idx: usize) -> Result<smite::bolt::ChannelId, ExecutorError> {
        match self.get_var(idx)? {
            Variable::ChannelId(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::ChannelId }),
        }
    }

    fn get_amount(&self, idx: usize) -> Result<u64, ExecutorError> {
        match self.get_var(idx)? {
            Variable::Amount(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::Amount }),
        }
    }

    fn get_block_height(&self, idx: usize) -> Result<u32, ExecutorError> {
        match self.get_var(idx)? {
            Variable::BlockHeight(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch {
                index: idx,
                expected: VariableType::BlockHeight,
            }),
        }
    }

    fn get_u16(&self, idx: usize) -> Result<u16, ExecutorError> {
        match self.get_var(idx)? {
            Variable::U16(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::U16 }),
        }
    }

    #[allow(dead_code)]
    fn get_u8(&self, idx: usize) -> Result<u8, ExecutorError> {
        match self.get_var(idx)? {
            Variable::U8(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::U8 }),
        }
    }

    fn get_bytes(&self, idx: usize) -> Result<Vec<u8>, ExecutorError> {
        match self.get_var(idx)? {
            Variable::Bytes(v) => Ok(v.clone()),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::Bytes }),
        }
    }

    fn get_features(&self, idx: usize) -> Result<Vec<u8>, ExecutorError> {
        match self.get_var(idx)? {
            Variable::Features(v) => Ok(v.clone()),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::Features }),
        }
    }

    fn get_point(&self, idx: usize) -> Result<PublicKey, ExecutorError> {
        match self.get_var(idx)? {
            Variable::Point(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::Point }),
        }
    }

    fn get_privkey(&self, idx: usize) -> Result<SecretKey, ExecutorError> {
        match self.get_var(idx)? {
            Variable::PrivateKey(v) => SecretKey::from_byte_array(*v).map_err(|_| {
                ExecutorError::TypeMismatch { index: idx, expected: VariableType::PrivateKey }
            }),
            _ => Err(ExecutorError::TypeMismatch {
                index: idx,
                expected: VariableType::PrivateKey,
            }),
        }
    }

    fn get_feerate_per_kw(&self, idx: usize) -> Result<u32, ExecutorError> {
        match self.get_var(idx)? {
            Variable::FeeratePerKw(v) => Ok(*v),
            _ => Err(ExecutorError::TypeMismatch {
                index: idx,
                expected: VariableType::FeeratePerKw,
            }),
        }
    }

    fn get_signed_amount(&self, idx: usize) -> Result<i64, ExecutorError> {
        match self.get_var(idx)? {
            Variable::SignedAmount(v) => Ok(*v),
            _ => {
                Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::SignedAmount })
            }
        }
    }

    fn get_message(&self, idx: usize) -> Result<Vec<u8>, ExecutorError> {
        match self.get_var(idx)? {
            Variable::Message(v) => Ok(v.clone()),
            _ => Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::Message }),
        }
    }

    fn get_accept_channel(&self, idx: usize) -> Result<&smite::bolt::AcceptChannel, ExecutorError> {
        match self.get_var(idx)? {
            Variable::AcceptChannel(v) => Ok(v),
            _ => {
                Err(ExecutorError::TypeMismatch { index: idx, expected: VariableType::AcceptChannel })
            }
        }
    }

    fn get_accept_channel2(&self, idx: usize) -> Result<&AcceptChannel2, ExecutorError> {
        match self.get_var(idx)? {
            Variable::AcceptChannel2(v) => Ok(v),
            _ => Err(ExecutorError::TypeMismatch {
                index: idx,
                expected: VariableType::AcceptChannel2,
            }),
        }
    }

    // -- Core executor --

    #[allow(clippy::too_many_lines)]
    fn execute_op(
        &mut self,
        op: &Operation,
        inputs: &[usize],
    ) -> Result<Option<Variable>, ExecutorError> {
        // Validate input count before any inputs[n] access.  AFL++ mutation can
        // produce deserialized programs with wrong input counts — reject them
        // gracefully instead of panicking on out-of-bounds indexing.
        let expected = op.input_types().len();
        if inputs.len() != expected {
            return Err(ExecutorError::WrongInputCount { expected, got: inputs.len() });
        }

        match op {
            // --- Load ---
            Operation::LoadAmount(v) => Ok(Some(Variable::Amount(*v))),
            Operation::LoadFeeratePerKw(v) => Ok(Some(Variable::FeeratePerKw(*v))),
            Operation::LoadBlockHeight(v) => Ok(Some(Variable::BlockHeight(*v))),
            Operation::LoadU16(v) => Ok(Some(Variable::U16(*v))),
            Operation::LoadU8(v) => Ok(Some(Variable::U8(*v))),
            Operation::LoadBytes(v) => Ok(Some(Variable::Bytes(v.clone()))),
            Operation::LoadFeatures(v) => Ok(Some(Variable::Features(v.clone()))),
            Operation::LoadPrivateKey(v) => Ok(Some(Variable::PrivateKey(*v))),
            Operation::LoadChannelId(v) => {
                Ok(Some(Variable::ChannelId(smite::bolt::ChannelId::new(*v))))
            }
            Operation::LoadSignedAmount(v) => Ok(Some(Variable::SignedAmount(*v))),
            Operation::LoadTargetPubkeyFromContext => {
                let pk = PublicKey::from_slice(&self.ctx.target_pubkey)
                    .map_err(|_| smite::bolt::BoltError::InvalidPublicKey(self.ctx.target_pubkey))?;
                Ok(Some(Variable::Point(pk)))
            }
            Operation::LoadChainHashFromContext => {
                Ok(Some(Variable::ChainHash(self.ctx.chain_hash)))
            }

            // --- Funding UTXO context loaders ---

            Operation::LoadFundingUtxoRawTx(n) => {
                let utxo = self.ctx.funding_utxos.get(*n).ok_or_else(|| {
                    // Out-of-bounds UTXO index — treat as a wrong-input-count fuzzing
                    // artifact so execution fails gracefully.
                    ExecutorError::WrongInputCount { expected: *n + 1, got: self.ctx.funding_utxos.len() }
                })?;
                Ok(Some(Variable::Bytes(utxo.raw_tx.clone())))
            }

            Operation::LoadFundingUtxoTxid(n) => {
                let utxo = self.ctx.funding_utxos.get(*n).ok_or_else(|| {
                    ExecutorError::WrongInputCount { expected: *n + 1, got: self.ctx.funding_utxos.len() }
                })?;
                Ok(Some(Variable::Bytes(utxo.txid.to_vec())))
            }

            Operation::LoadFundingUtxoVout(n) => {
                let utxo = self.ctx.funding_utxos.get(*n).ok_or_else(|| {
                    ExecutorError::WrongInputCount { expected: *n + 1, got: self.ctx.funding_utxos.len() }
                })?;
                Ok(Some(Variable::BlockHeight(utxo.vout)))
            }

            Operation::LoadFundingUtxoAmount(n) => {
                let utxo = self.ctx.funding_utxos.get(*n).ok_or_else(|| {
                    ExecutorError::WrongInputCount { expected: *n + 1, got: self.ctx.funding_utxos.len() }
                })?;
                Ok(Some(Variable::Amount(utxo.amount_sats)))
            }

            // --- Compute ---
            Operation::DerivePoint => {
                let Variable::PrivateKey(sk_bytes) = self.get_var(inputs[0])? else {
                    return Err(ExecutorError::TypeMismatch {
                        index: inputs[0],
                        expected: VariableType::PrivateKey,
                    });
                };
                let sk_bytes = *sk_bytes;
                let secp = Secp256k1::new();
                // Invalid private keys are skipped — executor returns None to
                // signal the calling scenario to skip this iteration.
                let sk = SecretKey::from_byte_array(sk_bytes)
                    .map_err(|_| smite::bolt::BoltError::Truncated { expected: 32, actual: 0 })?;
                let pk = PublicKey::from_secret_key(&secp, &sk);
                Ok(Some(Variable::Point(pk)))
            }

            Operation::ComputeTempChannelIdV2 => {
                use secp256k1::hashes::{sha256, Hash};

                let rev = self.get_point(inputs[0])?;
                let rev_bytes = rev.serialize(); // 33 bytes, compressed

                // CLN derive_tmp_channel_id formula (common/channel_id.c):
                //   der_keys = zeros[33] || revocation_basepoint[33]  // 66 bytes
                //   temp_id  = SHA256(der_keys)
                let mut der_keys = [0u8; 66];
                der_keys[33..66].copy_from_slice(&rev_bytes);

                let cid_hash = sha256::Hash::hash(&der_keys);
                let mut cid = [0u8; 32];
                cid.copy_from_slice(cid_hash.as_byte_array());

                Ok(Some(Variable::ChannelId(smite::bolt::ChannelId::new(cid))))
            }

            Operation::ComputeChannelIdV2 => {
                use secp256k1::hashes::{sha256, Hash};

                let our_rev = self.get_point(inputs[0])?;
                let their_rev = self.get_point(inputs[1])?;

                let our_bytes = our_rev.serialize();
                let their_bytes = their_rev.serialize();

                // CLN derive_channel_id_v2 formula:
                //   channel_id = SHA256(lesser_basepoint || greater_basepoint)
                let mut der_keys = [0u8; 66];
                if our_bytes <= their_bytes {
                    der_keys[..33].copy_from_slice(&our_bytes);
                    der_keys[33..].copy_from_slice(&their_bytes);
                } else {
                    der_keys[..33].copy_from_slice(&their_bytes);
                    der_keys[33..].copy_from_slice(&our_bytes);
                }

                let cid_hash = sha256::Hash::hash(&der_keys);
                let mut cid = [0u8; 32];
                cid.copy_from_slice(cid_hash.as_byte_array());

                Ok(Some(Variable::ChannelId(smite::bolt::ChannelId::new(cid))))
            }

            Operation::ExtractAcceptChannel(field) => {
                let msg = self.get_accept_channel(inputs[0])?.clone();
                let var = match field {
                    AcceptChannelField::TemporaryChannelId => {
                        Variable::ChannelId(msg.temporary_channel_id)
                    }
                    AcceptChannelField::DustLimitSatoshis => {
                        Variable::Amount(msg.dust_limit_satoshis)
                    }
                    AcceptChannelField::MaxHtlcValueInFlightMsat => {
                        Variable::Amount(msg.max_htlc_value_in_flight_msat)
                    }
                    AcceptChannelField::ChannelReserveSatoshis => {
                        Variable::Amount(msg.channel_reserve_satoshis)
                    }
                    AcceptChannelField::HtlcMinimumMsat => Variable::Amount(msg.htlc_minimum_msat),
                    AcceptChannelField::MinimumDepth => Variable::BlockHeight(msg.minimum_depth),
                    AcceptChannelField::ToSelfDelay => Variable::U16(msg.to_self_delay),
                    AcceptChannelField::MaxAcceptedHtlcs => Variable::U16(msg.max_accepted_htlcs),
                    AcceptChannelField::FundingPubkey => Variable::Point(msg.funding_pubkey),
                    AcceptChannelField::RevocationBasepoint => {
                        Variable::Point(msg.revocation_basepoint)
                    }
                    AcceptChannelField::PaymentBasepoint => Variable::Point(msg.payment_basepoint),
                    AcceptChannelField::DelayedPaymentBasepoint => {
                        Variable::Point(msg.delayed_payment_basepoint)
                    }
                    AcceptChannelField::HtlcBasepoint => Variable::Point(msg.htlc_basepoint),
                    AcceptChannelField::FirstPerCommitmentPoint => {
                        Variable::Point(msg.first_per_commitment_point)
                    }
                    AcceptChannelField::UpfrontShutdownScript => {
                        Variable::Bytes(msg.tlvs.upfront_shutdown_script.unwrap_or_default())
                    }
                    AcceptChannelField::ChannelType => {
                        Variable::Features(msg.tlvs.channel_type.unwrap_or_default())
                    }
                };
                Ok(Some(var))
            }

            Operation::ExtractAcceptChannel2(field) => {
                let msg = self.get_accept_channel2(inputs[0])?.clone();
                let var = match field {
                    AcceptChannel2Field::TemporaryChannelId => {
                        Variable::ChannelId(msg.temporary_channel_id)
                    }
                    AcceptChannel2Field::FundingSatoshis => Variable::Amount(msg.funding_satoshis),
                    AcceptChannel2Field::DustLimitSatoshis => {
                        Variable::Amount(msg.dust_limit_satoshis)
                    }
                    AcceptChannel2Field::MaxHtlcValueInFlightMsat => {
                        Variable::Amount(msg.max_htlc_value_in_flight_msat)
                    }
                    AcceptChannel2Field::HtlcMinimumMsat => {
                        Variable::Amount(msg.htlc_minimum_msat)
                    }
                    AcceptChannel2Field::MinimumDepth => Variable::BlockHeight(msg.minimum_depth),
                    AcceptChannel2Field::ToSelfDelay => Variable::U16(msg.to_self_delay),
                    AcceptChannel2Field::MaxAcceptedHtlcs => {
                        Variable::U16(msg.max_accepted_htlcs)
                    }
                    AcceptChannel2Field::FundingPubkey => Variable::Point(msg.funding_pubkey),
                    AcceptChannel2Field::RevocationBasepoint => {
                        Variable::Point(msg.revocation_basepoint)
                    }
                    AcceptChannel2Field::PaymentBasepoint => {
                        Variable::Point(msg.payment_basepoint)
                    }
                    AcceptChannel2Field::DelayedPaymentBasepoint => {
                        Variable::Point(msg.delayed_payment_basepoint)
                    }
                    AcceptChannel2Field::HtlcBasepoint => Variable::Point(msg.htlc_basepoint),
                    AcceptChannel2Field::FirstPerCommitmentPoint => {
                        Variable::Point(msg.first_per_commitment_point)
                    }
                    AcceptChannel2Field::SecondPerCommitmentPoint => {
                        Variable::Point(msg.second_per_commitment_point)
                    }
                    AcceptChannel2Field::UpfrontShutdownScript => {
                        Variable::Bytes(msg.tlvs.upfront_shutdown_script.unwrap_or_default())
                    }
                    AcceptChannel2Field::ChannelType => {
                        Variable::Features(msg.tlvs.channel_type.unwrap_or_default())
                    }
                };
                Ok(Some(var))
            }

            // --- Build dual funding messages ---
            Operation::BuildTxAddInput => {
                let channel_id = self.get_channel_id(inputs[0])?;
                // BOLT 2: opener serial_ids must be even. AFL mutates the
                // wire-encoded LoadAmount value freely, so mask the LSB here
                // to keep the parity invariant after mutation.
                let serial_id = self.get_amount(inputs[1])? & !1u64;
                let prevtx = self.get_bytes(inputs[2])?;
                let prevtx_vout = self.get_block_height(inputs[3])?;
                let sequence = self.get_block_height(inputs[4])?;

                // Record this input for BIP 143 signing later.
                // Compute the txid by hashing the prevtx bytes.
                let txid = btc_txid(&prevtx).unwrap_or([0u8; 32]);

                // Check if this UTXO matches any of our funding UTXOs — if so,
                // record signing info so ComputeFundingWitness can sign it.
                let signing = self
                    .ctx
                    .funding_utxos
                    .iter()
                    .find(|u| u.txid == txid && u.vout == prevtx_vout)
                    .map(|u| ItxSigningInfo {
                        amount_sats: u.amount_sats,
                        pubkey: u.pubkey,
                        privkey: u.privkey,
                    });

                // Remove any existing input with the same serial_id (BOLT 2: replace).
                self.itx_inputs.retain(|i| i.serial_id != serial_id);
                self.itx_inputs.push(ItxInput { serial_id, txid, vout: prevtx_vout, sequence, signing });

                let msg = TxAddInput { channel_id, serial_id, prevtx, prevtx_vout, sequence };
                Ok(Some(Variable::Message(Message::TxAddInput(msg).encode())))
            }

            Operation::BuildTxAddOutput => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let serial_id = self.get_amount(inputs[1])? & !1u64;
                let sats = self.get_amount(inputs[2])?;
                let script = self.get_bytes(inputs[3])?;

                // Record this output for BIP 143 hashOutputs.
                self.itx_outputs.retain(|o| o.serial_id != serial_id);
                self.itx_outputs.push(ItxOutput { serial_id, sats, script: script.clone() });

                let msg = TxAddOutput { channel_id, serial_id, sats, script };
                Ok(Some(Variable::Message(Message::TxAddOutput(msg).encode())))
            }

            Operation::BuildTxRemoveInput => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let serial_id = self.get_amount(inputs[1])? & !1u64;
                self.itx_inputs.retain(|i| i.serial_id != serial_id);
                let msg = TxRemoveInput { channel_id, serial_id };
                Ok(Some(Variable::Message(Message::TxRemoveInput(msg).encode())))
            }

            Operation::BuildTxRemoveOutput => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let serial_id = self.get_amount(inputs[1])? & !1u64;
                self.itx_outputs.retain(|o| o.serial_id != serial_id);
                let msg = TxRemoveOutput { channel_id, serial_id };
                Ok(Some(Variable::Message(Message::TxRemoveOutput(msg).encode())))
            }

            Operation::BuildTxComplete => {
                let msg = TxComplete { channel_id: self.get_channel_id(inputs[0])? };
                Ok(Some(Variable::Message(Message::TxComplete(msg).encode())))
            }

            Operation::BuildTxSignatures => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let txid_bytes = self.get_bytes(inputs[1])?;
                let witnesses_bytes = self.get_bytes(inputs[2])?;

                // Parse txid: use first 32 bytes, zero-pad if short.
                let mut txid_arr = [0u8; 32];
                let copy_len = txid_bytes.len().min(32);
                txid_arr[..copy_len].copy_from_slice(&txid_bytes[..copy_len]);

                use secp256k1::hashes::Hash;
                let txid = smite::bolt::Txid::from_byte_array(txid_arr);

                // Decode real witnesses from the bytes variable.
                // If the bytes are empty, we send zero witnesses (valid when
                // we contributed zero inputs, e.g., zero-contribution opener).
                let witnesses = if witnesses_bytes.is_empty() {
                    vec![]
                } else {
                    decode_witnesses(&witnesses_bytes)
                };

                let msg = TxSignatures { channel_id, txid, witnesses };
                Ok(Some(Variable::Message(Message::TxSignatures(msg).encode())))
            }

            Operation::BuildTxInitRbf => {
                let msg = TxInitRbf {
                    channel_id: self.get_channel_id(inputs[0])?,
                    locktime: self.get_block_height(inputs[1])?,
                    feerate_per_kw: self.get_feerate_per_kw(inputs[2])?,
                    tlvs: TxInitRbfTlvs {
                        funding_output_contribution: Some(self.get_signed_amount(inputs[3])?),
                        require_confirmed_inputs: self.get_u8(inputs[4])? != 0,
                    },
                };
                Ok(Some(Variable::Message(Message::TxInitRbf(msg).encode())))
            }

            Operation::BuildTxAckRbf => {
                let msg = TxAckRbf {
                    channel_id: self.get_channel_id(inputs[0])?,
                    tlvs: TxAckRbfTlvs {
                        funding_output_contribution: Some(self.get_signed_amount(inputs[1])?),
                        require_confirmed_inputs: self.get_u8(inputs[2])? != 0,
                    },
                };
                Ok(Some(Variable::Message(Message::TxAckRbf(msg).encode())))
            }

            Operation::BuildTxAbort => {
                let msg = smite::bolt::TxAbort {
                    channel_id: self.get_channel_id(inputs[0])?,
                    data: self.get_bytes(inputs[1])?,
                };
                Ok(Some(Variable::Message(Message::TxAbort(msg).encode())))
            }

            Operation::BuildShutdown => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let scriptpubkey = self.get_bytes(inputs[1])?;
                let msg = Shutdown::for_channel(channel_id, scriptpubkey);
                Ok(Some(Variable::Message(Message::Shutdown(msg).encode())))
            }

            Operation::BuildClosingSigned => {
                use secp256k1::ecdsa::Signature;
                let channel_id = self.get_channel_id(inputs[0])?;
                let fee_satoshis = self.get_amount(inputs[1])?;
                let sig_bytes = self.get_bytes(inputs[2])?;

                // Try to parse the user-supplied 64-byte compact signature.
                // Fall back to a deterministic valid signature so the message
                // always wire-encodes — CLN does the real validation anyway,
                // and AFL++ can mutate the encoded bytes downstream.
                let signature = if sig_bytes.len() == 64 {
                    Signature::from_compact(&sig_bytes).unwrap_or_else(|_| fallback_signature())
                } else {
                    fallback_signature()
                };

                let msg = ClosingSigned {
                    channel_id,
                    fee_satoshis,
                    signature,
                    tlvs: ClosingSignedTlvs::default(),
                };
                Ok(Some(Variable::Message(Message::ClosingSigned(msg).encode())))
            }

            Operation::BuildChannelReestablish => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let next_commitment_number = self.get_amount(inputs[1])?;
                let next_revocation_number = self.get_amount(inputs[2])?;
                let secret_bytes = self.get_bytes(inputs[3])?;
                let per_commitment_point = self.get_point(inputs[4])?;

                // your_last_per_commitment_secret must be exactly 32 bytes.
                // Pad with zeros or truncate so the message always wire-encodes.
                let mut secret = [0u8; 32];
                let copy_len = secret_bytes.len().min(32);
                secret[..copy_len].copy_from_slice(&secret_bytes[..copy_len]);

                let msg = ChannelReestablish {
                    channel_id,
                    next_commitment_number,
                    next_revocation_number,
                    your_last_per_commitment_secret: secret,
                    my_current_per_commitment_point: per_commitment_point,
                };
                Ok(Some(Variable::Message(Message::ChannelReestablish(msg).encode())))
            }

            Operation::RecvChannelReestablish => {
                recv_until(self.conn, |msg| match msg {
                    Message::ChannelReestablish(_) => RecvOutcome::Done(()),
                    Message::Warning(_) | Message::Error(_) => RecvOutcome::Abort(()),
                    _ => RecvOutcome::Continue,
                });
                Ok(None)
            }

            Operation::BuildCommitmentSigned => {
                let channel_id = self.get_channel_id(inputs[0])?;
                let payload = self.get_bytes(inputs[1])?;
                let msg = CommitmentSigned { channel_id, payload };
                Ok(Some(Variable::Message(Message::CommitmentSigned(msg).encode())))
            }

            Operation::BuildSignedCommitmentSigned => {
                use smite::bolt3;

                let channel_id = self.get_channel_id(inputs[0])?;
                let local_funding_secret = self.get_privkey(inputs[1])?;
                let remote_funding_pk = self.get_point(inputs[2])?;
                let local_revocation_basepoint = self.get_point(inputs[3])?;
                let local_payment_basepoint = self.get_point(inputs[4])?;
                let local_delayed_payment_basepoint = self.get_point(inputs[5])?;
                let remote_revocation_basepoint = self.get_point(inputs[6])?;
                let remote_payment_basepoint = self.get_point(inputs[7])?;
                let remote_delayed_payment_basepoint = self.get_point(inputs[8])?;
                let remote_per_commitment_point = self.get_point(inputs[9])?;
                let local_to_self_delay = self.get_u16(inputs[10])?;
                let feerate_per_kw = self.get_feerate_per_kw(inputs[11])?;
                let dust_limit_sat = self.get_amount(inputs[12])?;
                let local_contribution_sat = self.get_amount(inputs[13])?;
                let remote_contribution_sat = self.get_amount(inputs[14])?;

                let secp = Secp256k1::new();
                let local_funding_pk = PublicKey::from_secret_key(&secp, &local_funding_secret);

                // Reconstruct the funding tx in BOLT 2 serial-id order to
                // derive its txid + locate the funding output.
                let mut sorted_inputs = self.itx_inputs.clone();
                let mut sorted_outputs = self.itx_outputs.clone();
                sorted_inputs.sort_by_key(|i| i.serial_id);
                sorted_outputs.sort_by_key(|o| o.serial_id);

                let funding_script =
                    bolt3::p2wsh(&bolt3::funding_redeem_script(&local_funding_pk, &remote_funding_pk));

                let (funding_vout, funding_value_sat) = sorted_outputs
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.script == funding_script)
                    .map(|(i, o)| (i as u32, o.sats))
                    .ok_or(ExecutorError::WrongInputCount { expected: 1, got: 0 })?;

                let funding_txid = compute_funding_txid(
                    &sorted_inputs,
                    &sorted_outputs,
                    self.itx_locktime,
                );

                let params = bolt3::CommitTxParams {
                    funding_txid,
                    funding_vout,
                    funding_value_sat,
                    local_funding_pubkey: local_funding_pk,
                    remote_funding_pubkey: remote_funding_pk,
                    local_revocation_basepoint,
                    local_payment_basepoint,
                    local_delayed_payment_basepoint,
                    remote_revocation_basepoint,
                    remote_payment_basepoint,
                    remote_delayed_payment_basepoint,
                    remote_per_commitment_point,
                    local_to_self_delay,
                    feerate_per_kw,
                    dust_limit_sat,
                    local_is_opener: true,
                    local_contribution_sat,
                    remote_contribution_sat,
                    commitment_number: 0,
                };

                let sig = bolt3::sign_remote_commit_tx(&secp, &params, &local_funding_secret);

                // commitment_signed payload (after channel_id):
                //   signature(64) || num_htlcs(2 BE) || htlc_signatures[num*64]
                let mut payload = Vec::with_capacity(64 + 2);
                payload.extend_from_slice(&sig);
                payload.extend_from_slice(&0u16.to_be_bytes());

                let msg = CommitmentSigned { channel_id, payload };
                Ok(Some(Variable::Message(Message::CommitmentSigned(msg).encode())))
            }

            Operation::RecvCommitmentSigned => {
                recv_until(self.conn, |msg| match msg {
                    Message::CommitmentSigned(_) => RecvOutcome::Done(()),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(()),
                    _ => RecvOutcome::Continue,
                });
                Ok(None)
            }

            Operation::BuildSignedClosingSigned => {
                use smite::bolt3;

                let channel_id          = self.get_channel_id(inputs[0])?;
                let local_funding_secret = self.get_privkey(inputs[1])?;
                let remote_funding_pk   = self.get_point(inputs[2])?;
                let our_script          = self.get_bytes(inputs[3])?;
                let their_script        = self.get_bytes(inputs[4])?;
                let our_balance_sat     = self.get_amount(inputs[5])?;
                let their_balance_sat   = self.get_amount(inputs[6])?;
                let dust_limit_sat      = self.get_amount(inputs[7])?;
                let fee_satoshis        = self.get_amount(inputs[8])?;

                let secp = Secp256k1::new();
                let local_funding_pk = PublicKey::from_secret_key(&secp, &local_funding_secret);

                // Reconstruct funding tx (BOLT 2 serial-id order) to derive
                // funding outpoint + value, exactly like BuildSignedCommitmentSigned.
                let mut sorted_inputs = self.itx_inputs.clone();
                let mut sorted_outputs = self.itx_outputs.clone();
                sorted_inputs.sort_by_key(|i| i.serial_id);
                sorted_outputs.sort_by_key(|o| o.serial_id);

                let funding_redeem =
                    bolt3::funding_redeem_script(&local_funding_pk, &remote_funding_pk);
                let funding_script = bolt3::p2wsh(&funding_redeem);

                let (funding_vout, funding_value_sat) = sorted_outputs
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.script == funding_script)
                    .map(|(i, o)| (i as u32, o.sats))
                    .ok_or(ExecutorError::WrongInputCount { expected: 1, got: 0 })?;

                let funding_txid = compute_funding_txid(
                    &sorted_inputs,
                    &sorted_outputs,
                    self.itx_locktime,
                );

                // Build close_tx the way CLN's create_close_tx does:
                // we're the opener, so subtract fee from our balance
                // (saturating — under-funded fees still produce a wire-
                // valid message that exercises CLN's validation path).
                let our_after_fee = our_balance_sat.saturating_sub(fee_satoshis);

                let mut outputs: Vec<bolt3::TxOut> = Vec::with_capacity(2);
                if our_after_fee >= dust_limit_sat {
                    outputs.push(bolt3::TxOut {
                        value_sat: our_after_fee,
                        script_pubkey: our_script.clone(),
                    });
                }
                if their_balance_sat >= dust_limit_sat {
                    outputs.push(bolt3::TxOut {
                        value_sat: their_balance_sat,
                        script_pubkey: their_script.clone(),
                    });
                }
                bolt3::sort_outputs_bip69(&mut outputs);

                // BITCOIN_TX_DEFAULT_SEQUENCE = 0xFFFFFFFF (final, no RBF).
                let close_in = bolt3::TxIn {
                    prev_txid: funding_txid,
                    prev_vout: funding_vout,
                    sequence: 0xFFFF_FFFF,
                };

                let sighash = bolt3::sighash_segwit_v0(
                    std::slice::from_ref(&close_in),
                    &outputs,
                    2,                  // version
                    0,                  // locktime
                    0,                  // input_index
                    &funding_redeem,    // scriptCode
                    funding_value_sat,
                    1,                  // SIGHASH_ALL
                );

                let signature = bolt3::sign_sighash(&local_funding_secret, &sighash);

                let msg = ClosingSigned {
                    channel_id,
                    fee_satoshis,
                    signature,
                    tlvs: ClosingSignedTlvs::default(),
                };
                Ok(Some(Variable::Message(Message::ClosingSigned(msg).encode())))
            }

            Operation::ComputeP2WPKHScript => {
                use secp256k1::hashes::{Hash, hash160};

                let pk = self.get_point(inputs[0])?;
                let compressed = pk.serialize(); // 33 bytes
                // HASH160 = RIPEMD160(SHA256(pubkey))
                let h160 = hash160::Hash::hash(&compressed);
                let hash_bytes = h160.as_byte_array();
                // P2WPKH scriptpubkey: OP_0(0x00) OP_PUSH20(0x14) <20-byte-hash>
                let mut script = Vec::with_capacity(22);
                script.push(0x00); // OP_0
                script.push(0x14); // OP_PUSH20 (push 20 bytes)
                script.extend_from_slice(hash_bytes);
                Ok(Some(Variable::Bytes(script)))
            }

            Operation::ComputeFundingScriptP2WSH => {
                use secp256k1::hashes::{Hash, sha256};

                let our_pk = self.get_point(inputs[0])?.serialize();
                let their_pk = self.get_point(inputs[1])?.serialize();

                // bitcoin_redeem_2of2 sorts pubkeys lexicographically.
                let (lo, hi) = if our_pk <= their_pk {
                    (our_pk, their_pk)
                } else {
                    (their_pk, our_pk)
                };

                // redeem = OP_2 <push33> lo <push33> hi OP_2 OP_CHECKMULTISIG
                let mut redeem = Vec::with_capacity(71);
                redeem.push(0x52); // OP_2
                redeem.push(0x21); // push 33 bytes
                redeem.extend_from_slice(&lo);
                redeem.push(0x21);
                redeem.extend_from_slice(&hi);
                redeem.push(0x52); // OP_2
                redeem.push(0xae); // OP_CHECKMULTISIG

                let h = sha256::Hash::hash(&redeem);
                // P2WSH scriptpubkey: OP_0 OP_PUSH32 <32-byte-hash>
                let mut script = Vec::with_capacity(34);
                script.push(0x00); // OP_0
                script.push(0x20); // push 32 bytes
                script.extend_from_slice(h.as_byte_array());
                Ok(Some(Variable::Bytes(script)))
            }

            Operation::AddAmounts => {
                let a = self.get_amount(inputs[0])?;
                let b = self.get_amount(inputs[1])?;
                Ok(Some(Variable::Amount(a.saturating_add(b))))
            }

            Operation::BuildOpenChannel => {
                let msg = OpenChannel {
                    chain_hash: self.get_chain_hash(inputs[0])?,
                    temporary_channel_id: self.get_channel_id(inputs[1])?,
                    funding_satoshis: self.get_amount(inputs[2])?,
                    push_msat: self.get_amount(inputs[3])?,
                    dust_limit_satoshis: self.get_amount(inputs[4])?,
                    max_htlc_value_in_flight_msat: self.get_amount(inputs[5])?,
                    channel_reserve_satoshis: self.get_amount(inputs[6])?,
                    htlc_minimum_msat: self.get_amount(inputs[7])?,
                    feerate_per_kw: self.get_feerate_per_kw(inputs[8])?,
                    to_self_delay: self.get_u16(inputs[9])?,
                    max_accepted_htlcs: self.get_u16(inputs[10])?,
                    funding_pubkey: self.get_point(inputs[11])?,
                    revocation_basepoint: self.get_point(inputs[12])?,
                    payment_basepoint: self.get_point(inputs[13])?,
                    delayed_payment_basepoint: self.get_point(inputs[14])?,
                    htlc_basepoint: self.get_point(inputs[15])?,
                    first_per_commitment_point: self.get_point(inputs[16])?,
                    channel_flags: self.get_u8(inputs[17])?,
                    tlvs: OpenChannelTlvs {
                        upfront_shutdown_script: {
                            let b = self.get_bytes(inputs[18])?;
                            if b.is_empty() { None } else { Some(b) }
                        },
                        channel_type: {
                            let f = self.get_features(inputs[19])?;
                            if f.is_empty() { None } else { Some(f) }
                        },
                    },
                };
                Ok(Some(Variable::Message(Message::OpenChannel(msg).encode())))
            }

            Operation::BuildOpenChannel2 => {
                let locktime = self.get_block_height(inputs[10])?;
                // Track the funding transaction locktime for BIP 143.
                self.itx_locktime = locktime;

                let msg = OpenChannel2 {
                    chain_hash: self.get_chain_hash(inputs[0])?,
                    temporary_channel_id: self.get_channel_id(inputs[1])?,
                    funding_feerate_perkw: self.get_feerate_per_kw(inputs[2])?,
                    commitment_feerate_perkw: self.get_feerate_per_kw(inputs[3])?,
                    funding_satoshis: self.get_amount(inputs[4])?,
                    dust_limit_satoshis: self.get_amount(inputs[5])?,
                    max_htlc_value_in_flight_msat: self.get_amount(inputs[6])?,
                    htlc_minimum_msat: self.get_amount(inputs[7])?,
                    to_self_delay: self.get_u16(inputs[8])?,
                    max_accepted_htlcs: self.get_u16(inputs[9])?,
                    locktime,
                    funding_pubkey: self.get_point(inputs[11])?,
                    revocation_basepoint: self.get_point(inputs[12])?,
                    payment_basepoint: self.get_point(inputs[13])?,
                    delayed_payment_basepoint: self.get_point(inputs[14])?,
                    htlc_basepoint: self.get_point(inputs[15])?,
                    first_per_commitment_point: self.get_point(inputs[16])?,
                    second_per_commitment_point: self.get_point(inputs[17])?,
                    channel_flags: self.get_u8(inputs[18])?,
                    tlvs: OpenChannel2Tlvs {
                        upfront_shutdown_script: {
                            let b = self.get_bytes(inputs[19])?;
                            if b.is_empty() { None } else { Some(b) }
                        },
                        channel_type: {
                            let f = self.get_features(inputs[20])?;
                            if f.is_empty() { None } else { Some(f) }
                        },
                        require_confirmed_inputs: false,
                    },
                };
                Ok(Some(Variable::Message(Message::OpenChannel2(msg).encode())))
            }

            // --- BIP 143 P2WPKH witness computation ---

            Operation::ComputeFundingWitness => {
                // Sort all tracked inputs and outputs by serial_id (BOLT 2: lexicographic
                // ordering of the negotiated transaction).
                let mut sorted_inputs = self.itx_inputs.clone();
                let mut sorted_outputs = self.itx_outputs.clone();
                sorted_inputs.sort_by_key(|i| i.serial_id);
                sorted_outputs.sort_by_key(|o| o.serial_id);

                let secp = Secp256k1::signing_only();
                let locktime = self.itx_locktime;

                // Build one Witness per input in serial_id order.
                // For our inputs (with signing info), compute a real BIP 143 sig.
                // For CLN's inputs, emit an empty witness (not our job to sign those).
                let mut witnesses: Vec<Witness> = Vec::new();

                for (idx, inp) in sorted_inputs.iter().enumerate() {
                    if let Some(ref sign) = inp.signing {
                        // Compute BIP 143 P2WPKH sighash.
                        let sighash = bip143_p2wpkh_sighash(
                            &sorted_inputs,
                            &sorted_outputs,
                            idx,
                            sign.amount_sats,
                            &sign.pubkey,
                            locktime,
                        );

                        // Sign with secp256k1 ECDSA.
                        let sk = match SecretKey::from_byte_array(sign.privkey) {
                            Ok(sk) => sk,
                            Err(_) => {
                                // Invalid privkey in context (shouldn't happen in
                                // production, but AFL++ may mutate context bytes).
                                witnesses.push(Witness { items: vec![] });
                                continue;
                            }
                        };

                        let msg_hash = secp256k1::Message::from_digest(sighash);
                        let sig = secp.sign_ecdsa(msg_hash, &sk);

                        // DER-encode and append SIGHASH_ALL (0x01).
                        let mut der_sig = sig.serialize_der().to_vec();
                        der_sig.push(0x01); // SIGHASH_ALL

                        // Witness: [<der_sig_with_hashtype>, <compressed_pubkey>]
                        witnesses.push(Witness {
                            items: vec![der_sig, sign.pubkey.to_vec()],
                        });
                    } else {
                        // CLN's input — we don't sign it.
                        witnesses.push(Witness { items: vec![] });
                    }
                }

                Ok(Some(Variable::Bytes(encode_witnesses(&witnesses))))
            }

            // --- Send / Recv ---
            Operation::SendMessage => {
                let bytes = self.get_message(inputs[0])?;
                self.conn.send_message(&bytes)?;
                Ok(None)
            }

            Operation::RecvAcceptChannel => {
                loop {
                    let bytes = self.conn.recv_message()?;
                    let msg = Message::decode(&bytes)?;
                    match msg {
                        Message::AcceptChannel(m) => return Ok(Some(Variable::AcceptChannel(m))),
                        // Interleaved messages — skip silently.
                        Message::Unknown { .. }
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::GossipTimestampFilter(_)
                        | Message::Warning(_) => continue,
                        other => {
                            return Err(ExecutorError::UnexpectedMessage {
                                expected: "accept_channel",
                                got: other.msg_type(),
                            })
                        }
                    }
                }
            }

            Operation::RecvAcceptChannel2 => {
                loop {
                    let bytes = self.conn.recv_message()?;
                    let msg = Message::decode(&bytes)?;
                    match msg {
                        Message::AcceptChannel2(m) => {
                            return Ok(Some(Variable::AcceptChannel2(m)));
                        }
                        Message::Unknown { .. }
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::GossipTimestampFilter(_)
                        | Message::Warning(_) => continue,
                        other => {
                            return Err(ExecutorError::UnexpectedMessage {
                                expected: "accept_channel2",
                                got: other.msg_type(),
                            })
                        }
                    }
                }
            }

            Operation::RecvTxAddInput => {
                loop {
                    let bytes = self.conn.recv_message()?;
                    let msg = Message::decode(&bytes)?;
                    match msg {
                        Message::TxAddInput(_) => return Ok(None),
                        Message::Unknown { .. }
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::GossipTimestampFilter(_)
                        | Message::Warning(_) => continue,
                        _ => return Ok(None),
                    }
                }
            }

            Operation::RecvTxAddOutput => {
                loop {
                    let bytes = self.conn.recv_message()?;
                    let msg = Message::decode(&bytes)?;
                    match msg {
                        Message::TxAddOutput(_) => return Ok(None),
                        Message::Unknown { .. }
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::GossipTimestampFilter(_)
                        | Message::Warning(_) => continue,
                        _ => return Ok(None),
                    }
                }
            }

            Operation::RecvTxComplete => {
                loop {
                    let bytes = self.conn.recv_message()?;
                    let msg = Message::decode(&bytes)?;
                    match msg {
                        // CommitmentSigned implies CLN has finished interactive-tx
                        // and moved on; treat it as "tx_complete done" so the
                        // outer RecvCommitmentSigned step doesn't get starved.
                        Message::TxComplete(_)
                        | Message::TxAbort(_)
                        | Message::CommitmentSigned(_) => return Ok(None),

                        // Drain and RECORD CLN's interactive-tx contributions so
                        // ComputeFundingWitness can include them in BIP 143.
                        Message::TxAddInput(m) => {
                            let txid = btc_txid(&m.prevtx).unwrap_or([0u8; 32]);
                            self.itx_inputs.retain(|i| i.serial_id != m.serial_id);
                            self.itx_inputs.push(ItxInput {
                                serial_id: m.serial_id,
                                txid,
                                vout: m.prevtx_vout,
                                sequence: m.sequence,
                                signing: None, // CLN's input — we don't hold the key
                            });
                            continue;
                        }
                        Message::TxAddOutput(m) => {
                            self.itx_outputs.retain(|o| o.serial_id != m.serial_id);
                            self.itx_outputs.push(ItxOutput {
                                serial_id: m.serial_id,
                                sats: m.sats,
                                script: m.script,
                            });
                            continue;
                        }
                        Message::TxRemoveInput(m) => {
                            self.itx_inputs.retain(|i| i.serial_id != m.serial_id);
                            continue;
                        }
                        Message::TxRemoveOutput(m) => {
                            self.itx_outputs.retain(|o| o.serial_id != m.serial_id);
                            continue;
                        }

                        // Interleaved BOLT 1 messages — skip silently.
                        Message::Unknown { .. }
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::GossipTimestampFilter(_)
                        | Message::Warning(_) => continue,

                        // `error` from the peer (e.g., UTXO validation failed).
                        // Return Ok so execution continues to tx_signatures.
                        Message::Error(_) => return Ok(None),

                        other => {
                            return Err(ExecutorError::UnexpectedMessage {
                                expected: "tx_complete",
                                got: other.msg_type(),
                            })
                        }
                    }
                }
            }

            Operation::RecvTxSignatures => {
                // Try to receive tx_signatures from CLN (CLN sends first when it
                // has the lower funding_pubkey).  Extract the real txid so our
                // responding tx_signatures can echo it — CLN verifies txid matches.
                //
                // Returns zeros on timeout/error so the program always continues.
                let result: Result<[u8; 32], ExecutorError> = (|| {
                    loop {
                        let bytes = self.conn.recv_message()?;
                        let msg = Message::decode(&bytes)?;
                        match msg {
                            Message::TxSignatures(m) => {
                                use secp256k1::hashes::Hash;
                                return Ok(m.txid.to_byte_array());
                            }
                            Message::Unknown { .. }
                            | Message::Ping(_)
                            | Message::Pong(_)
                            | Message::GossipTimestampFilter(_)
                            | Message::Warning(_) => continue,
                            Message::Error(_) | Message::TxAbort(_) => {
                                return Ok([0u8; 32]);
                            }
                            _ => return Ok([0u8; 32]),
                        }
                    }
                })();
                let txid = result.unwrap_or([0u8; 32]);
                Ok(Some(Variable::Bytes(txid.to_vec())))
            }

            Operation::RecvTxRemoveInput => {
                let serial = recv_until(&mut self.conn, |msg| match msg {
                    Message::TxRemoveInput(m) => RecvOutcome::Done(m.serial_id),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(0),
                    _ => RecvOutcome::Continue,
                })
                .unwrap_or(0);
                Ok(Some(Variable::Amount(serial)))
            }

            Operation::RecvTxRemoveOutput => {
                let serial = recv_until(&mut self.conn, |msg| match msg {
                    Message::TxRemoveOutput(m) => RecvOutcome::Done(m.serial_id),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(0),
                    _ => RecvOutcome::Continue,
                })
                .unwrap_or(0);
                Ok(Some(Variable::Amount(serial)))
            }

            Operation::RecvTxInitRbf => {
                let _ = recv_until(&mut self.conn, |msg| match msg {
                    Message::TxInitRbf(_) => RecvOutcome::Done(()),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(()),
                    _ => RecvOutcome::Continue,
                });
                Ok(None)
            }

            Operation::RecvTxAckRbf => {
                let _ = recv_until(&mut self.conn, |msg| match msg {
                    Message::TxAckRbf(_) => RecvOutcome::Done(()),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(()),
                    _ => RecvOutcome::Continue,
                });
                Ok(None)
            }

            Operation::RecvTxAbort => {
                let _ = recv_until(&mut self.conn, |msg| match msg {
                    Message::TxAbort(_) | Message::Error(_) => RecvOutcome::Done(()),
                    _ => RecvOutcome::Continue,
                });
                Ok(None)
            }

            Operation::RecvShutdown => {
                let script = recv_until(&mut self.conn, |msg| match msg {
                    Message::Shutdown(m) => RecvOutcome::Done(m.scriptpubkey),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(Vec::new()),
                    _ => RecvOutcome::Continue,
                })
                .unwrap_or_default();
                Ok(Some(Variable::Bytes(script)))
            }

            Operation::RecvClosingSigned => {
                let fee = recv_until(&mut self.conn, |msg| match msg {
                    Message::ClosingSigned(m) => RecvOutcome::Done(m.fee_satoshis),
                    Message::Error(_) | Message::TxAbort(_) => RecvOutcome::Abort(0),
                    _ => RecvOutcome::Continue,
                })
                .unwrap_or(0);
                Ok(Some(Variable::Amount(fee)))
            }
        }
    }
}

/// Returns a deterministic, wire-valid 64-byte ECDSA signature.
///
/// Used as a placeholder when `BuildClosingSigned` receives malformed signature
/// bytes — CLN will reject it, but the message still encodes and reaches CLN's
/// signature-validation code path (which is what we want to fuzz).
fn fallback_signature() -> secp256k1::ecdsa::Signature {
    use secp256k1::{Message as Secp256k1Message, Secp256k1, SecretKey, ecdsa::Signature};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_byte_array([1u8; 32]).expect("constant key is in range");
    let msg = Secp256k1Message::from_digest([0u8; 32]);
    Signature::from_compact(&secp.sign_ecdsa(msg, &sk).serialize_compact())
        .expect("freshly signed signature is always valid")
}

/// Outcome of inspecting one received message in [`recv_until`].
enum RecvOutcome<T> {
    /// Target message arrived; return the extracted value.
    Done(T),
    /// Peer signaled abort/error; return the fallback value.
    Abort(T),
    /// Unrelated benign message (ping, gossip, warning); keep looping.
    Continue,
}

/// Drain messages from the connection until `match_fn` returns `Done` or
/// `Abort`, transient I/O errors stop the loop, or the message is unexpected.
/// Returns `None` only on connection error so callers can fall back gracefully.
fn recv_until<T>(
    conn: &mut NoiseConnection,
    mut match_fn: impl FnMut(Message) -> RecvOutcome<T>,
) -> Option<T> {
    loop {
        let bytes = conn.recv_message().ok()?;
        let msg = Message::decode(&bytes).ok()?;
        match match_fn(msg) {
            RecvOutcome::Done(v) | RecvOutcome::Abort(v) => return Some(v),
            RecvOutcome::Continue => continue,
        }
    }
}
