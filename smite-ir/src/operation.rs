//! IR operations.

use std::fmt;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::VariableType;

/// An IR operation.  Each instruction in a program contains one operation plus
/// input variable indices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    // -- Load: produce a variable from an embedded literal or the context --
    /// Load a satoshi or millisatoshi amount.
    LoadAmount(u64),
    /// Load a fee rate in sat/kw.
    LoadFeeratePerKw(u32),
    /// Load a block height or count.
    LoadBlockHeight(u32),
    /// Load a u16 protocol parameter (e.g., `to_self_delay`).
    LoadU16(u16),
    /// Load a u8 protocol parameter (e.g., `channel_flags`).
    LoadU8(u8),
    /// Load raw bytes.
    LoadBytes(Vec<u8>),
    /// Load feature bits.
    LoadFeatures(Vec<u8>),
    /// Load a secp256k1 private key.  The executor validates that the bytes are
    /// in range `[1, curve_order)` and skips if not.
    LoadPrivateKey([u8; 32]),
    /// Load a 32-byte channel identifier.
    LoadChannelId([u8; 32]),
    /// Load the target node's public key from the program context.
    LoadTargetPubkeyFromContext,
    /// Load the chain hash from the program context.
    LoadChainHashFromContext,

    // -- Compute: derive a variable from inputs --
    /// Derive a compressed public key from a private key.
    /// Input: `PrivateKey`.
    DerivePoint,
    /// Compute the BOLT 2 v2 temporary channel ID.
    ///
    /// In dual-funding (`open_channel2`), the `temporary_channel_id` is NOT a
    /// free random value — the responder recomputes it from the opener's
    /// `revocation_basepoint` and rejects if it doesn't match.
    ///
    /// Formula (matches CLN `derive_tmp_channel_id` in `common/channel_id.c`):
    ///   `temp_channel_id = SHA256(zeros[33] || revocation_basepoint[33])`
    ///
    /// Inputs (1):
    ///   0: opener's `revocation_basepoint` (`Point`)
    ComputeTempChannelIdV2,
    /// Compute the full channel_id after accept_channel2 is received.
    ///
    /// CLN `derive_channel_id_v2` formula:
    ///   channel_id = SHA256(lesser_revocation_basepoint || greater_revocation_basepoint)
    /// where lesser/greater is lexicographic order of the 33-byte compressed keys.
    ///
    /// Inputs (2):
    ///   0: our `revocation_basepoint` (`Point`)
    ///   1: their `revocation_basepoint` (`Point`) — extracted from accept_channel2
    ComputeChannelIdV2,
    /// Extract a field from a parsed `accept_channel` response.
    /// Input: `AcceptChannel`.
    ExtractAcceptChannel(AcceptChannelField),
    /// Extract a field from a parsed `accept_channel2` response.
    /// Input: `AcceptChannel2`.
    ExtractAcceptChannel2(AcceptChannel2Field),

    // -- Build: construct a BOLT message from inputs --
    /// Build an `open_channel` message (BOLT 2, type 32).
    ///
    /// Inputs (20, matching wire order):
    ///   0: `chain_hash` (`ChainHash`)
    ///   1: `temporary_channel_id` (`ChannelId`)
    ///   2: `funding_satoshis` (`Amount`)
    ///   3: `push_msat` (`Amount`)
    ///   4: `dust_limit_satoshis` (`Amount`)
    ///   5: `max_htlc_value_in_flight_msat` (`Amount`)
    ///   6: `channel_reserve_satoshis` (`Amount`)
    ///   7: `htlc_minimum_msat` (`Amount`)
    ///   8: `feerate_per_kw` (`FeeratePerKw`)
    ///   9: `to_self_delay` (`U16`)
    ///  10: `max_accepted_htlcs` (`U16`)
    ///  11: `funding_pubkey` (`Point`)
    ///  12: `revocation_basepoint` (`Point`)
    ///  13: `payment_basepoint` (`Point`)
    ///  14: `delayed_payment_basepoint` (`Point`)
    ///  15: `htlc_basepoint` (`Point`)
    ///  16: `first_per_commitment_point` (`Point`)
    ///  17: `channel_flags` (`U8`)
    ///  18: `upfront_shutdown_script` (`Bytes`, empty = omit TLV)
    ///  19: `channel_type` (`Features`, empty = omit TLV)
    BuildOpenChannel,

    // -- Build: dual funding messages --

    /// Build an `open_channel2` message (BOLT 2, type 64).
    ///
    /// Inputs (21, matching wire order):
    ///   0: `chain_hash` (`ChainHash`)
    ///   1: `temporary_channel_id` (`ChannelId`)
    ///   2: `funding_feerate_perkw` (`FeeratePerKw`)
    ///   3: `commitment_feerate_perkw` (`FeeratePerKw`)
    ///   4: `funding_satoshis` (`Amount`)
    ///   5: `dust_limit_satoshis` (`Amount`)
    ///   6: `max_htlc_value_in_flight_msat` (`Amount`)
    ///   7: `htlc_minimum_msat` (`Amount`)
    ///   8: `to_self_delay` (`U16`)
    ///   9: `max_accepted_htlcs` (`U16`)
    ///  10: `locktime` (`BlockHeight`)
    ///  11: `funding_pubkey` (`Point`)
    ///  12: `revocation_basepoint` (`Point`)
    ///  13: `payment_basepoint` (`Point`)
    ///  14: `delayed_payment_basepoint` (`Point`)
    ///  15: `htlc_basepoint` (`Point`)
    ///  16: `first_per_commitment_point` (`Point`)
    ///  17: `second_per_commitment_point` (`Point`)
    ///  18: `channel_flags` (`U8`)
    ///  19: `upfront_shutdown_script` (`Bytes`, empty = omit TLV)
    ///  20: `channel_type` (`Features`, empty = omit TLV)
    BuildOpenChannel2,

    /// Build a `tx_add_input` message (BOLT 2, type 66).
    ///
    /// Inputs (5):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `serial_id` (`Amount` as u64 — even for initiator, odd for responder)
    ///   2: `prevtx` (`Bytes` — serialized previous transaction)
    ///   3: `prevtx_vout` (`BlockHeight` as u32)
    ///   4: `sequence` (`BlockHeight` as u32)
    BuildTxAddInput,

    /// Build a `tx_add_output` message (BOLT 2, type 67).
    ///
    /// Inputs (4):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `serial_id` (`Amount` as u64)
    ///   2: `sats` (`Amount`)
    ///   3: `script` (`Bytes`)
    BuildTxAddOutput,

    /// Build a `tx_remove_input` message (BOLT 2, type 68).
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `serial_id` (`Amount` as u64)
    BuildTxRemoveInput,

    /// Build a `tx_remove_output` message (BOLT 2, type 69).
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `serial_id` (`Amount` as u64)
    BuildTxRemoveOutput,

    /// Build a `tx_complete` message (BOLT 2, type 70).
    ///
    /// Inputs (1):
    ///   0: `channel_id` (`ChannelId`)
    BuildTxComplete,

    /// Build a `tx_signatures` message (BOLT 2, type 71).
    ///
    /// Inputs (3):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `txid` (`Bytes` — 32-byte transaction ID)
    ///   2: `witnesses` (`Bytes` — serialized witness stack)
    BuildTxSignatures,

    /// Build a `tx_init_rbf` message (BOLT 2, type 72).
    ///
    /// Inputs (4):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `locktime` (`BlockHeight`)
    ///   2: `feerate_per_kw` (`FeeratePerKw`)
    ///   3: `funding_output_contribution` (`SignedAmount`, i64 satoshis)
    BuildTxInitRbf,

    /// Build a `tx_ack_rbf` message (BOLT 2, type 73).
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `funding_output_contribution` (`SignedAmount`, i64 satoshis)
    BuildTxAckRbf,

    /// Build a `tx_abort` message (BOLT 2, type 74).
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `data` (`Bytes` — human-readable abort reason)
    BuildTxAbort,

    /// Build a `shutdown` message (BOLT 2, type 38).
    ///
    /// Sent after the interactive-tx phase to initiate cooperative close.
    /// CLN's `handle_peer_shutdown` handles this message.
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `scriptpubkey` (`Bytes` — scriptpubkey to receive funds; use P2WPKH/P2WSH/empty)
    BuildShutdown,

    /// Build a `closing_signed` message (BOLT 2, type 39).
    ///
    /// Sent after both peers have exchanged `shutdown` to negotiate the
    /// cooperative close fee.  Drives `closingd.c::handle_peer_closing_signed`.
    ///
    /// Inputs (3):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `fee_satoshis` (`Amount`)
    ///   2: `signature` (`Bytes` — 64-byte compact ECDSA; on parse failure
    ///      the executor substitutes a deterministic valid placeholder so
    ///      the message still wire-encodes)
    BuildClosingSigned,

    // -- Act: side effects against the target --
    /// Send an encoded message over the connection.
    /// Input: `Message`.
    SendMessage,
    /// Receive and parse an `accept_channel` response.
    /// Produces an `AcceptChannel` compound variable.
    RecvAcceptChannel,
    /// Receive and parse an `accept_channel2` response.
    /// Produces an `AcceptChannel2` compound variable.
    RecvAcceptChannel2,
    /// Receive a `tx_add_input` message from the peer (no output variable).
    RecvTxAddInput,
    /// Receive a `tx_add_output` message from the peer (no output variable).
    RecvTxAddOutput,
    /// Receive a `tx_complete` message from the peer (no output variable).
    ///
    /// Drains and discards any interleaved `tx_add_input`, `tx_add_output`,
    /// `tx_remove_input`, or `tx_remove_output` messages from the peer (CLN
    /// may send these before its own `tx_complete`).  Also handles `error`
    /// gracefully so execution can continue to the `tx_signatures` exchange.
    RecvTxComplete,
    /// Receive a `tx_remove_input` message from the peer and extract its
    /// `serial_id`.  Lets follow-up programs echo/replay the same serial.
    ///
    /// Output: `Amount` (peer's serial_id, or 0 on timeout/wrong message).
    RecvTxRemoveInput,
    /// Receive a `tx_remove_output` message from the peer and extract its
    /// `serial_id`.
    ///
    /// Output: `Amount` (peer's serial_id, or 0 on timeout/wrong message).
    RecvTxRemoveOutput,
    /// Receive a `tx_init_rbf` message from the peer (CLN-initiated RBF).
    /// Advances the state machine; no output variable.
    RecvTxInitRbf,
    /// Receive a `tx_ack_rbf` message from the peer (CLN's response to our
    /// `tx_init_rbf`).  Signals CLN accepted the new round; no output variable.
    RecvTxAckRbf,
    /// Receive a `tx_abort` message from the peer.  Lets the program continue
    /// past peer aborts instead of treating them as protocol errors.
    /// No output variable.
    RecvTxAbort,
    /// Receive a `shutdown` message from the peer and extract its
    /// `scriptpubkey`.  Required to feed `closing_signed` rounds during
    /// cooperative close fuzzing.
    ///
    /// Output: `Bytes` (peer's scriptpubkey, empty on timeout/wrong message).
    RecvShutdown,
    /// Receive a `closing_signed` message from the peer and extract its
    /// `fee_satoshis`.  Used to drive subsequent fee-negotiation rounds.
    ///
    /// Output: `Amount` (peer's proposed fee, 0 on timeout/wrong message).
    RecvClosingSigned,
    /// Receive a `tx_signatures` message from the peer and extract its txid.
    ///
    /// In BOLT 2 dual-funding, the party with the **lesser** `funding_pubkey`
    /// (lexicographic order) sends `tx_signatures` first.  After both sides
    /// have sent `tx_complete`, if CLN has the lower funding pubkey, CLN sends
    /// its `tx_signatures` before us.  This operation receives that message
    /// and returns the 32-byte txid as `Bytes`.
    ///
    /// **Error handling**: If the peer does not send `tx_signatures` (either
    /// because we are supposed to send first, or due to a protocol error),
    /// this operation returns `[0u8; 32]` rather than failing.  This lets
    /// the program continue and still send `tx_signatures`, ensuring CLN's
    /// `handle_tx_sigs` is triggered even in the degenerate path.
    ///
    /// Output: `Bytes` (32-byte txid, or zeros on failure/ordering mismatch).
    RecvTxSignatures,
    /// Load a signed satoshi amount (for RBF `funding_output_contribution`).
    LoadSignedAmount(i64),

    // -- Funding UTXO context loaders --

    /// Load the raw previous-transaction bytes for funding UTXO at index N.
    ///
    /// The bytes come from `ProgramContext.funding_utxos[N].raw_tx` and are
    /// used verbatim as the `prevtx` field in `BuildTxAddInput`.
    ///
    /// Output: `Bytes`
    LoadFundingUtxoRawTx(usize),

    /// Load the 32-byte txid (Bitcoin internal byte order) for funding UTXO at index N.
    ///
    /// Output: `Bytes` (32 bytes)
    LoadFundingUtxoTxid(usize),

    /// Load the output index (vout) for funding UTXO at index N.
    ///
    /// Output: `BlockHeight` (u32)
    LoadFundingUtxoVout(usize),

    /// Load the satoshi amount for funding UTXO at index N.
    ///
    /// Output: `Amount` (u64)
    LoadFundingUtxoAmount(usize),

    /// Build a `channel_reestablish` message (BOLT 1, type 136).
    ///
    /// Sent after reconnecting to re-synchronize channel state with the peer.
    /// Drives `handle_peer_reestablish` in `dualopend.c` and `closingd.c`.
    ///
    /// Inputs (5):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `next_commitment_number` (`Amount` as u64 — 1 for a fresh channel)
    ///   2: `next_revocation_number` (`Amount` as u64 — 0 for a fresh channel)
    ///   3: `your_last_per_commitment_secret` (`Bytes` — 32 bytes, all-zeros
    ///      when next_revocation_number == 0)
    ///   4: `my_current_per_commitment_point` (`Point` — our current
    ///      per-commitment point, i.e. `first_per_commitment_point` for a fresh
    ///      channel that has not yet revoked any commitment)
    BuildChannelReestablish,

    /// Receive a `channel_reestablish` from the peer.
    ///
    /// Drains the incoming stream until a `channel_reestablish` (type 136) is
    /// seen, skipping intervening BOLT 1 housekeeping messages.  No output
    /// variable is produced — the purpose is to consume the peer's response so
    /// the connection does not fall out of step.
    RecvChannelReestablish,

    /// Build a `commitment_signed` message (BOLT 2, type 132).
    ///
    /// The payload following the channel_id is supplied as raw bytes (signature
    /// + num_htlcs + htlc_signatures). Since we cannot produce a valid signature
    /// against CLN's expected commitment transaction, the bytes are typically a
    /// stub that drives CLN's signature-validation paths in
    /// `dualopend.c::handle_peer_commitment_signed` and
    /// `channeld.c::handle_peer_commit_sig`.
    ///
    /// Inputs (2):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `payload` (`Bytes` — sig(64) + num_htlcs(2) + htlc_sigs(num*64))
    BuildCommitmentSigned,

    /// Receive and discard a `commitment_signed` message from the peer.
    ///
    /// CLN sends `commitment_signed` after `tx_complete` exchange to commit to
    /// the funding transaction. This op drains the incoming stream until
    /// `commitment_signed` (type 132) is seen, skipping interleaved housekeeping
    /// messages. No output variable is produced.
    RecvCommitmentSigned,

    /// Build a *cryptographically valid* `commitment_signed` for the
    /// initial commit (commitment_number = 0, no HTLCs, anchor channels).
    ///
    /// The executor reconstructs the funding tx from its tracked
    /// interactive-tx state (`itx_inputs`/`itx_outputs` sorted by
    /// `serial_id` per BOLT 2), locates the funding output by matching the
    /// 2-of-2 P2WSH script, then constructs the *remote* commitment tx and
    /// signs the BIP 143 sighash with our funding privkey.
    ///
    /// Assumes the modern CLN dual-funding default: anchor outputs +
    /// `option_static_remotekey`, no HTLCs, smite is the opener.
    ///
    /// Inputs (15):
    ///   0:  `channel_id` (`ChannelId`)
    ///   1:  local funding privkey (`PrivateKey`)
    ///   2:  remote funding pubkey (`Point`)  — from accept_channel2
    ///   3:  local revocation basepoint (`Point`)
    ///   4:  local payment basepoint (`Point`)
    ///   5:  local delayed_payment basepoint (`Point`)
    ///   6:  remote revocation basepoint (`Point`) — from accept_channel2
    ///   7:  remote payment basepoint (`Point`)    — from accept_channel2
    ///   8:  remote delayed_payment basepoint (`Point`) — from accept_channel2
    ///   9:  remote per-commitment point (`Point`) — from accept_channel2
    ///  10:  local `to_self_delay` (`U16`) — what we sent in open_channel2
    ///  11:  commitment feerate (`FeeratePerKw`) — from open_channel2
    ///  12:  dust limit sat (`Amount`)
    ///  13:  our contribution sat (`Amount`)
    ///  14:  their contribution sat (`Amount`)
    BuildSignedCommitmentSigned,

    /// Build a *cryptographically valid* `closing_signed` (BOLT 2, type 39).
    ///
    /// The executor reconstructs the funding outpoint from its tracked
    /// interactive-tx state (same path as `BuildSignedCommitmentSigned`),
    /// builds the cooperative-close tx exactly the way CLN's
    /// `common/close_tx.c::create_close_tx` does (version 2, locktime 0,
    /// one input with `BITCOIN_TX_DEFAULT_SEQUENCE` = 0xFFFFFFFF, two
    /// possible outputs trimmed individually below `dust_limit`, then
    /// BIP 69 sorted), computes the BIP 143 sighash with the funding
    /// 2-of-2 redeem script as the scriptCode, and signs with the local
    /// funding privkey.  Drives `closingd.c::handle_peer_closing_signed`
    /// past its signature-validation gate so the full close path runs.
    ///
    /// Assumes smite is the opener (so the fee is subtracted from our
    /// balance), which matches every dual-funding seed that reaches the
    /// close phase.
    ///
    /// Inputs (9):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: local funding privkey (`PrivateKey`)
    ///   2: remote funding pubkey (`Point`) — from accept_channel2
    ///   3: our shutdown scriptpubkey (`Bytes`) — what we sent in shutdown
    ///   4: their shutdown scriptpubkey (`Bytes`) — from `RecvShutdown`
    ///   5: our balance sat (`Amount`) — usually = our `funding_sats`
    ///   6: their balance sat (`Amount`) — usually CLN's contribution
    ///   7: dust_limit_sat (`Amount`)
    ///   8: fee_satoshis (`Amount`)
    BuildSignedClosingSigned,

    /// Compute a P2WPKH scriptpubkey from a compressed secp256k1 public key.
    ///
    /// Formula (BIP 141):
    ///   `OP_0 OP_PUSH20 HASH160(compressed_pubkey)`
    ///   = `[0x00, 0x14] || RIPEMD160(SHA256(compressed_pubkey))`
    ///
    /// Produces a 22-byte scriptpubkey that is accepted by CLN's
    /// `is_known_scripttype` check in `common/scriptpubkey.c`.  Use this to
    /// build a semantically correct (key-derived) `upfront_shutdown_script` in
    /// `open_channel2` instead of a hardcoded byte vector.
    ///
    /// Input: `Point` (compressed secp256k1 public key, 33 bytes)
    /// Output: `Bytes` (22-byte P2WPKH scriptpubkey)
    ComputeP2WPKHScript,

    /// Compute BIP 143 P2WPKH witnesses for all our inputs in the negotiated
    /// funding transaction and encode them for use in `BuildTxSignatures`.
    ///
    /// The executor uses state tracked during `BuildTxAddInput`,
    /// `BuildTxAddOutput`, and `RecvTxComplete` (CLN's contributions) to:
    ///   1. Sort all inputs and outputs by serial_id (BOLT 2 ordering).
    ///   2. Compute BIP 143 sighash for each input where the fuzzer holds the key.
    ///   3. Sign with secp256k1 ECDSA (DER + SIGHASH_ALL byte).
    ///   4. Encode witnesses in the `TxSignatures` wire format.
    ///
    /// Returns zeros (empty witness list) if no signed inputs were tracked.
    ///
    /// Output: `Bytes` (encoded witness list for `BuildTxSignatures`)
    ComputeFundingWitness,

    /// Compute the P2WSH scriptpubkey of the BOLT 3 2-of-2 funding multisig.
    ///
    /// CLN's `find_funding_output` (openingd/dualopend.c:2776-2814) computes:
    ///   `wscript     = bitcoin_redeem_2of2(our_funding_pubkey, their_funding_pubkey)`
    ///   `scriptpkey  = scriptpubkey_p2wsh(wscript)`
    /// and rejects the channel-open if no PSBT output matches `scriptpkey`.
    ///
    /// `bitcoin_redeem_2of2` sorts the two pubkeys lexicographically by their
    /// 33-byte compressed serialization, so this op produces the same canonical
    /// script regardless of input argument order.
    ///
    /// Inputs (2):
    ///   0: our funding_pubkey (`Point`)
    ///   1: their funding_pubkey (`Point`) — extracted from accept_channel2
    /// Output: `Bytes` (34-byte P2WSH scriptpubkey: `OP_0 OP_PUSH32 SHA256(redeem)`)
    ComputeFundingScriptP2WSH,

    /// Add two satoshi amounts (saturating on overflow).
    ///
    /// Used to compute the funding-output value as
    /// `our_funding_satoshis + their_funding_satoshis` before passing it to
    /// `BuildTxAddOutput`.
    ///
    /// Inputs (2):
    ///   0: a (`Amount`)
    ///   1: b (`Amount`)
    /// Output: `Amount` (a.saturating_add(b))
    AddAmounts,
}

/// Fields that can be extracted from an `AcceptChannel2` compound variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptChannel2Field {
    TemporaryChannelId,
    FundingSatoshis,
    DustLimitSatoshis,
    MaxHtlcValueInFlightMsat,
    HtlcMinimumMsat,
    MinimumDepth,
    ToSelfDelay,
    MaxAcceptedHtlcs,
    FundingPubkey,
    RevocationBasepoint,
    PaymentBasepoint,
    DelayedPaymentBasepoint,
    HtlcBasepoint,
    FirstPerCommitmentPoint,
    SecondPerCommitmentPoint,
    UpfrontShutdownScript,
    ChannelType,
}

impl fmt::Display for AcceptChannel2Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AcceptChannel2Field {
    /// All variants.
    pub const ALL: &[Self] = &[
        Self::TemporaryChannelId,
        Self::FundingSatoshis,
        Self::DustLimitSatoshis,
        Self::MaxHtlcValueInFlightMsat,
        Self::HtlcMinimumMsat,
        Self::MinimumDepth,
        Self::ToSelfDelay,
        Self::MaxAcceptedHtlcs,
        Self::FundingPubkey,
        Self::RevocationBasepoint,
        Self::PaymentBasepoint,
        Self::DelayedPaymentBasepoint,
        Self::HtlcBasepoint,
        Self::FirstPerCommitmentPoint,
        Self::SecondPerCommitmentPoint,
        Self::UpfrontShutdownScript,
        Self::ChannelType,
    ];

    /// Returns the variable type produced by extracting this field.
    #[must_use]
    pub fn output_type(self) -> VariableType {
        match self {
            Self::TemporaryChannelId => VariableType::ChannelId,
            Self::FundingSatoshis
            | Self::DustLimitSatoshis
            | Self::MaxHtlcValueInFlightMsat
            | Self::HtlcMinimumMsat => VariableType::Amount,
            Self::MinimumDepth => VariableType::BlockHeight,
            Self::ToSelfDelay | Self::MaxAcceptedHtlcs => VariableType::U16,
            Self::FundingPubkey
            | Self::RevocationBasepoint
            | Self::PaymentBasepoint
            | Self::DelayedPaymentBasepoint
            | Self::HtlcBasepoint
            | Self::FirstPerCommitmentPoint
            | Self::SecondPerCommitmentPoint => VariableType::Point,
            Self::UpfrontShutdownScript => VariableType::Bytes,
            Self::ChannelType => VariableType::Features,
        }
    }
}

/// Fields that can be extracted from an `AcceptChannel` compound variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcceptChannelField {
    TemporaryChannelId,
    DustLimitSatoshis,
    MaxHtlcValueInFlightMsat,
    ChannelReserveSatoshis,
    HtlcMinimumMsat,
    MinimumDepth,
    ToSelfDelay,
    MaxAcceptedHtlcs,
    FundingPubkey,
    RevocationBasepoint,
    PaymentBasepoint,
    DelayedPaymentBasepoint,
    HtlcBasepoint,
    FirstPerCommitmentPoint,
    UpfrontShutdownScript,
    ChannelType,
}

impl fmt::Display for AcceptChannelField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AcceptChannelField {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::TemporaryChannelId,
        Self::DustLimitSatoshis,
        Self::MaxHtlcValueInFlightMsat,
        Self::ChannelReserveSatoshis,
        Self::HtlcMinimumMsat,
        Self::MinimumDepth,
        Self::ToSelfDelay,
        Self::MaxAcceptedHtlcs,
        Self::FundingPubkey,
        Self::RevocationBasepoint,
        Self::PaymentBasepoint,
        Self::DelayedPaymentBasepoint,
        Self::HtlcBasepoint,
        Self::FirstPerCommitmentPoint,
        Self::UpfrontShutdownScript,
        Self::ChannelType,
    ];

    /// Returns the variable type produced by extracting this field.
    #[must_use]
    pub fn output_type(self) -> VariableType {
        match self {
            Self::TemporaryChannelId => VariableType::ChannelId,
            Self::DustLimitSatoshis
            | Self::MaxHtlcValueInFlightMsat
            | Self::ChannelReserveSatoshis
            | Self::HtlcMinimumMsat => VariableType::Amount,
            Self::MinimumDepth => VariableType::BlockHeight,
            Self::ToSelfDelay | Self::MaxAcceptedHtlcs => VariableType::U16,
            Self::FundingPubkey
            | Self::RevocationBasepoint
            | Self::PaymentBasepoint
            | Self::DelayedPaymentBasepoint
            | Self::HtlcBasepoint
            | Self::FirstPerCommitmentPoint => VariableType::Point,
            Self::UpfrontShutdownScript => VariableType::Bytes,
            Self::ChannelType => VariableType::Features,
        }
    }
}

/// Format a byte slice as a hex string. Returns an empty string for empty
/// input.
fn format_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        write!(s, "{b:02x}").expect("write to string");
    }
    s
}

/// Print an Operation. Operations that take no variable inputs include parens
/// (e.g., `LoadAmount(100000)`, `RecvAcceptChannel()`). Operations that do take
/// inputs omit parens so `Program::Display` can append them `(v0, v1, ...)`.
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadAmount(v) => write!(f, "LoadAmount({v})"),
            Self::LoadFeeratePerKw(v) => write!(f, "LoadFeeratePerKw({v})"),
            Self::LoadBlockHeight(v) => write!(f, "LoadBlockHeight({v})"),
            Self::LoadU16(v) => write!(f, "LoadU16({v})"),
            Self::LoadU8(v) => write!(f, "LoadU8({v})"),
            Self::LoadBytes(b) => write!(f, "LoadBytes({})", format_hex(b)),
            Self::LoadFeatures(b) => write!(f, "LoadFeatures({})", format_hex(b)),
            Self::LoadPrivateKey(b) => write!(f, "LoadPrivateKey({})", format_hex(b)),
            Self::LoadChannelId(b) => write!(f, "LoadChannelId({})", format_hex(b)),
            Self::LoadTargetPubkeyFromContext => write!(f, "LoadTargetPubkeyFromContext()"),
            Self::LoadChainHashFromContext => write!(f, "LoadChainHashFromContext()"),
            Self::RecvAcceptChannel => write!(f, "RecvAcceptChannel()"),
            Self::RecvAcceptChannel2 => write!(f, "RecvAcceptChannel2()"),
            Self::RecvTxAddInput => write!(f, "RecvTxAddInput()"),
            Self::RecvTxAddOutput => write!(f, "RecvTxAddOutput()"),
            Self::RecvTxComplete => write!(f, "RecvTxComplete()"),
            Self::RecvTxRemoveInput => write!(f, "RecvTxRemoveInput()"),
            Self::RecvTxRemoveOutput => write!(f, "RecvTxRemoveOutput()"),
            Self::RecvTxInitRbf => write!(f, "RecvTxInitRbf()"),
            Self::RecvTxAckRbf => write!(f, "RecvTxAckRbf()"),
            Self::RecvTxAbort => write!(f, "RecvTxAbort()"),
            Self::RecvShutdown => write!(f, "RecvShutdown()"),
            Self::RecvClosingSigned => write!(f, "RecvClosingSigned()"),
            Self::RecvTxSignatures => write!(f, "RecvTxSignatures()"),
            Self::LoadSignedAmount(v) => write!(f, "LoadSignedAmount({v})"),
            Self::LoadFundingUtxoRawTx(n) => write!(f, "LoadFundingUtxoRawTx({n})"),
            Self::LoadFundingUtxoTxid(n) => write!(f, "LoadFundingUtxoTxid({n})"),
            Self::LoadFundingUtxoVout(n) => write!(f, "LoadFundingUtxoVout({n})"),
            Self::LoadFundingUtxoAmount(n) => write!(f, "LoadFundingUtxoAmount({n})"),
            Self::ComputeFundingWitness => write!(f, "ComputeFundingWitness()"),
            Self::ComputeFundingScriptP2WSH => write!(f, "ComputeFundingScriptP2WSH"),
            Self::AddAmounts => write!(f, "AddAmounts"),
            Self::RecvChannelReestablish => write!(f, "RecvChannelReestablish()"),
            Self::ComputeP2WPKHScript => write!(f, "ComputeP2WPKHScript"),
            // Operations with inputs: parens added by Program::Display.
            Self::DerivePoint => write!(f, "DerivePoint"),
            Self::ComputeTempChannelIdV2 => write!(f, "ComputeTempChannelIdV2"),
            Self::ComputeChannelIdV2 => write!(f, "ComputeChannelIdV2"),
            Self::ExtractAcceptChannel(field) => write!(f, "Extract{field}"),
            Self::ExtractAcceptChannel2(field) => write!(f, "Extract2{field}"),
            Self::BuildOpenChannel => write!(f, "BuildOpenChannel"),
            Self::BuildOpenChannel2 => write!(f, "BuildOpenChannel2"),
            Self::BuildTxAddInput => write!(f, "BuildTxAddInput"),
            Self::BuildTxAddOutput => write!(f, "BuildTxAddOutput"),
            Self::BuildTxRemoveInput => write!(f, "BuildTxRemoveInput"),
            Self::BuildTxRemoveOutput => write!(f, "BuildTxRemoveOutput"),
            Self::BuildTxComplete => write!(f, "BuildTxComplete"),
            Self::BuildTxSignatures => write!(f, "BuildTxSignatures"),
            Self::BuildTxInitRbf => write!(f, "BuildTxInitRbf"),
            Self::BuildTxAckRbf => write!(f, "BuildTxAckRbf"),
            Self::BuildTxAbort => write!(f, "BuildTxAbort"),
            Self::BuildShutdown => write!(f, "BuildShutdown"),
            Self::BuildClosingSigned => write!(f, "BuildClosingSigned"),
            Self::BuildChannelReestablish => write!(f, "BuildChannelReestablish"),
            Self::BuildCommitmentSigned => write!(f, "BuildCommitmentSigned"),
            Self::BuildSignedCommitmentSigned => write!(f, "BuildSignedCommitmentSigned"),
            Self::BuildSignedClosingSigned => write!(f, "BuildSignedClosingSigned"),
            Self::RecvCommitmentSigned => write!(f, "RecvCommitmentSigned()"),
            Self::SendMessage => write!(f, "SendMessage"),
        }
    }
}

impl Operation {
    /// Returns the variable type produced by this operation, or `None` for void
    /// operations (e.g., `SendMessage`).
    #[must_use]
    pub fn output_type(&self) -> Option<VariableType> {
        match self {
            Self::LoadAmount(_) => Some(VariableType::Amount),
            Self::LoadFeeratePerKw(_) => Some(VariableType::FeeratePerKw),
            Self::LoadBlockHeight(_) => Some(VariableType::BlockHeight),
            Self::LoadU16(_) => Some(VariableType::U16),
            Self::LoadU8(_) => Some(VariableType::U8),
            Self::LoadBytes(_) => Some(VariableType::Bytes),
            Self::LoadFeatures(_) => Some(VariableType::Features),
            Self::LoadPrivateKey(_) => Some(VariableType::PrivateKey),
            Self::LoadChannelId(_) => Some(VariableType::ChannelId),
            Self::LoadTargetPubkeyFromContext | Self::DerivePoint => Some(VariableType::Point),
            Self::ComputeTempChannelIdV2 | Self::ComputeChannelIdV2 => Some(VariableType::ChannelId),
            Self::LoadChainHashFromContext => Some(VariableType::ChainHash),
            Self::ExtractAcceptChannel(field) => Some(field.output_type()),
            Self::ExtractAcceptChannel2(field) => Some(field.output_type()),
            Self::BuildOpenChannel
            | Self::BuildOpenChannel2
            | Self::BuildTxAddInput
            | Self::BuildTxAddOutput
            | Self::BuildTxRemoveInput
            | Self::BuildTxRemoveOutput
            | Self::BuildTxComplete
            | Self::BuildTxSignatures
            | Self::BuildTxInitRbf
            | Self::BuildTxAckRbf
            | Self::BuildTxAbort
            | Self::BuildShutdown
            | Self::BuildClosingSigned
            | Self::BuildChannelReestablish
            | Self::BuildCommitmentSigned
            | Self::BuildSignedCommitmentSigned
            | Self::BuildSignedClosingSigned => Some(VariableType::Message),
            Self::ComputeP2WPKHScript => Some(VariableType::Bytes),
            Self::SendMessage
            | Self::RecvTxAddInput
            | Self::RecvTxAddOutput
            | Self::RecvTxComplete
            | Self::RecvTxInitRbf
            | Self::RecvTxAckRbf
            | Self::RecvTxAbort
            | Self::RecvChannelReestablish
            | Self::RecvCommitmentSigned => None,
            Self::RecvAcceptChannel => Some(VariableType::AcceptChannel),
            Self::RecvAcceptChannel2 => Some(VariableType::AcceptChannel2),
            Self::LoadSignedAmount(_) => Some(VariableType::SignedAmount),
            // Returns the 32-byte txid extracted from CLN's tx_signatures.
            Self::RecvTxSignatures => Some(VariableType::Bytes),
            // Peer's serial_id from a tx_remove_{input,output}.
            Self::RecvTxRemoveInput | Self::RecvTxRemoveOutput => Some(VariableType::Amount),
            // Peer's scriptpubkey from a shutdown.
            Self::RecvShutdown => Some(VariableType::Bytes),
            // Peer's proposed fee_satoshis from a closing_signed.
            Self::RecvClosingSigned => Some(VariableType::Amount),
            Self::LoadFundingUtxoRawTx(_) => Some(VariableType::Bytes),
            Self::LoadFundingUtxoTxid(_) => Some(VariableType::Bytes),
            Self::LoadFundingUtxoVout(_) => Some(VariableType::BlockHeight),
            Self::LoadFundingUtxoAmount(_) => Some(VariableType::Amount),
            Self::ComputeFundingWitness => Some(VariableType::Bytes),
            Self::ComputeFundingScriptP2WSH => Some(VariableType::Bytes),
            Self::AddAmounts => Some(VariableType::Amount),
        }
    }

    /// Returns the expected variable types for each input position.
    #[must_use]
    pub fn input_types(&self) -> Vec<VariableType> {
        match self {
            Self::LoadAmount(_)
            | Self::LoadFeeratePerKw(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::LoadSignedAmount(_)
            | Self::RecvAcceptChannel
            | Self::RecvAcceptChannel2
            | Self::RecvTxAddInput
            | Self::RecvTxAddOutput
            | Self::RecvTxComplete
            | Self::RecvTxRemoveInput
            | Self::RecvTxRemoveOutput
            | Self::RecvTxInitRbf
            | Self::RecvTxAckRbf
            | Self::RecvTxAbort
            | Self::RecvShutdown
            | Self::RecvClosingSigned
            | Self::RecvTxSignatures
            | Self::RecvChannelReestablish
            | Self::RecvCommitmentSigned
            | Self::LoadFundingUtxoRawTx(_)
            | Self::LoadFundingUtxoTxid(_)
            | Self::LoadFundingUtxoVout(_)
            | Self::LoadFundingUtxoAmount(_)
            | Self::ComputeFundingWitness => vec![],

            Self::DerivePoint => vec![VariableType::PrivateKey],
            Self::ComputeP2WPKHScript => vec![VariableType::Point],
            Self::ComputeFundingScriptP2WSH => vec![
                VariableType::Point, // our funding_pubkey
                VariableType::Point, // their funding_pubkey
            ],
            Self::AddAmounts => vec![VariableType::Amount, VariableType::Amount],
            Self::ComputeTempChannelIdV2 => vec![
                VariableType::Point, // revocation_basepoint (opener's)
            ],
            Self::ComputeChannelIdV2 => vec![
                VariableType::Point, // our revocation_basepoint
                VariableType::Point, // their revocation_basepoint (from accept_channel2)
            ],
            Self::ExtractAcceptChannel(_) => vec![VariableType::AcceptChannel],
            Self::ExtractAcceptChannel2(_) => vec![VariableType::AcceptChannel2],
            Self::SendMessage => vec![VariableType::Message],

            Self::BuildTxAddInput => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Amount,       // serial_id (u64)
                VariableType::Bytes,        // prevtx
                VariableType::BlockHeight,  // prevtx_vout (u32)
                VariableType::BlockHeight,  // sequence (u32)
            ],
            Self::BuildTxAddOutput => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Amount,       // serial_id (u64)
                VariableType::Amount,       // sats
                VariableType::Bytes,        // script
            ],
            Self::BuildTxRemoveInput | Self::BuildTxRemoveOutput => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Amount,       // serial_id (u64)
            ],
            Self::BuildTxComplete => vec![
                VariableType::ChannelId,    // channel_id
            ],
            Self::BuildTxSignatures => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Bytes,        // txid (32 bytes)
                VariableType::Bytes,        // witnesses (serialized)
            ],
            Self::BuildTxInitRbf => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::BlockHeight,  // locktime
                VariableType::FeeratePerKw, // feerate_per_kw
                VariableType::SignedAmount, // funding_output_contribution
                VariableType::U8,           // require_confirmed_inputs (0=false, nonzero=true)
            ],
            Self::BuildTxAckRbf => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::SignedAmount, // funding_output_contribution
                VariableType::U8,           // require_confirmed_inputs (0=false, nonzero=true)
            ],
            Self::BuildTxAbort => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Bytes,        // data
            ],
            Self::BuildShutdown => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Bytes,        // scriptpubkey (empty or P2WPKH/P2WSH)
            ],
            Self::BuildClosingSigned => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Amount,       // fee_satoshis
                VariableType::Bytes,        // signature (64-byte compact ECDSA)
            ],
            Self::BuildChannelReestablish => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Amount,       // next_commitment_number (u64)
                VariableType::Amount,       // next_revocation_number (u64)
                VariableType::Bytes,        // your_last_per_commitment_secret (32 bytes)
                VariableType::Point,        // my_current_per_commitment_point
            ],
            Self::BuildCommitmentSigned => vec![
                VariableType::ChannelId,    // channel_id
                VariableType::Bytes,        // payload (sig(64) + num_htlcs(2) + htlc_sigs)
            ],
            Self::BuildSignedCommitmentSigned => vec![
                VariableType::ChannelId,    //  0: channel_id
                VariableType::PrivateKey,   //  1: local funding privkey
                VariableType::Point,        //  2: remote funding pubkey
                VariableType::Point,        //  3: local revocation basepoint
                VariableType::Point,        //  4: local payment basepoint
                VariableType::Point,        //  5: local delayed_payment basepoint
                VariableType::Point,        //  6: remote revocation basepoint
                VariableType::Point,        //  7: remote payment basepoint
                VariableType::Point,        //  8: remote delayed_payment basepoint
                VariableType::Point,        //  9: remote per-commitment point
                VariableType::U16,          // 10: local to_self_delay
                VariableType::FeeratePerKw, // 11: commitment feerate
                VariableType::Amount,       // 12: dust limit sat
                VariableType::Amount,       // 13: our contribution sat
                VariableType::Amount,       // 14: their contribution sat
            ],
            Self::BuildSignedClosingSigned => vec![
                VariableType::ChannelId,    // 0: channel_id
                VariableType::PrivateKey,   // 1: local funding privkey
                VariableType::Point,        // 2: remote funding pubkey
                VariableType::Bytes,        // 3: our shutdown scriptpubkey
                VariableType::Bytes,        // 4: their shutdown scriptpubkey
                VariableType::Amount,       // 5: our balance sat
                VariableType::Amount,       // 6: their balance sat
                VariableType::Amount,       // 7: dust_limit_sat
                VariableType::Amount,       // 8: fee_satoshis
            ],

            Self::BuildOpenChannel2 => vec![
                VariableType::ChainHash,    // chain_hash
                VariableType::ChannelId,    // temporary_channel_id
                VariableType::FeeratePerKw, // funding_feerate_perkw
                VariableType::FeeratePerKw, // commitment_feerate_perkw
                VariableType::Amount,       // funding_satoshis
                VariableType::Amount,       // dust_limit_satoshis
                VariableType::Amount,       // max_htlc_value_in_flight_msat
                VariableType::Amount,       // htlc_minimum_msat
                VariableType::U16,          // to_self_delay
                VariableType::U16,          // max_accepted_htlcs
                VariableType::BlockHeight,  // locktime
                VariableType::Point,        // funding_pubkey
                VariableType::Point,        // revocation_basepoint
                VariableType::Point,        // payment_basepoint
                VariableType::Point,        // delayed_payment_basepoint
                VariableType::Point,        // htlc_basepoint
                VariableType::Point,        // first_per_commitment_point
                VariableType::Point,        // second_per_commitment_point
                VariableType::U8,           // channel_flags
                VariableType::Bytes,        // upfront_shutdown_script (empty = omit)
                VariableType::Features,     // channel_type (empty = omit)
            ],
            Self::BuildOpenChannel => vec![
                VariableType::ChainHash,    // chain_hash
                VariableType::ChannelId,    // temporary_channel_id
                VariableType::Amount,       // funding_satoshis
                VariableType::Amount,       // push_msat
                VariableType::Amount,       // dust_limit_satoshis
                VariableType::Amount,       // max_htlc_value_in_flight_msat
                VariableType::Amount,       // channel_reserve_satoshis
                VariableType::Amount,       // htlc_minimum_msat
                VariableType::FeeratePerKw, // feerate_per_kw
                VariableType::U16,          // to_self_delay
                VariableType::U16,          // max_accepted_htlcs
                VariableType::Point,        // funding_pubkey
                VariableType::Point,        // revocation_basepoint
                VariableType::Point,        // payment_basepoint
                VariableType::Point,        // delayed_payment_basepoint
                VariableType::Point,        // htlc_basepoint
                VariableType::Point,        // first_per_commitment_point
                VariableType::U8,           // channel_flags
                VariableType::Bytes,        // upfront_shutdown_script
                VariableType::Features,     // channel_type
            ],
        }
    }

    /// Returns extraction operations for compound variable types.
    ///
    /// For example, `RecvAcceptChannel` produces an `AcceptChannel` compound
    /// variable, so this returns `ExtractAcceptChannel` operations for each
    /// field.  Non-compound operations return an empty vec.
    #[must_use]
    pub fn extractable_fields(&self) -> Vec<(Operation, VariableType)> {
        match self {
            Self::RecvAcceptChannel => AcceptChannelField::ALL
                .iter()
                .map(|&f| (Self::ExtractAcceptChannel(f), f.output_type()))
                .collect(),
            Self::RecvAcceptChannel2 => AcceptChannel2Field::ALL
                .iter()
                .map(|&f| (Self::ExtractAcceptChannel2(f), f.output_type()))
                .collect(),
            _ => vec![],
        }
    }

    /// Returns true if this operation has parameters that can be mutated
    /// by `OperationParamMutator`.
    #[must_use]
    pub fn is_param_mutable(&self) -> bool {
        matches!(
            self,
            Self::LoadAmount(_)
                | Self::LoadFeeratePerKw(_)
                | Self::LoadBlockHeight(_)
                | Self::LoadU16(_)
                | Self::LoadU8(_)
                | Self::LoadBytes(_)
                | Self::LoadFeatures(_)
                | Self::LoadPrivateKey(_)
                | Self::LoadChannelId(_)
                | Self::LoadSignedAmount(_)
                | Self::ExtractAcceptChannel(_)
                | Self::ExtractAcceptChannel2(_)
                | Self::LoadFundingUtxoRawTx(_)
                | Self::LoadFundingUtxoTxid(_)
                | Self::LoadFundingUtxoVout(_)
                | Self::LoadFundingUtxoAmount(_)
        )
    }
}
