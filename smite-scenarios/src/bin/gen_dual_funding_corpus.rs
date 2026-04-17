//! Seed corpus generator for the dual-funding fuzzer.
//!
//! Generates postcard-encoded [`smite_ir::Program`] files that AFL++ uses as
//! its initial corpus.  Having a valid corpus is critical: without it AFL++
//! spends the first hours mutating random bytes, all of which fall through to
//! the seed-fallback path in `DualFundingScenario::run` instead of exercising
//! the real BOLT 2 state machine.
//!
//! # Usage
//!
//! ```bash
//! # Default output dir: corpus/dual-funding
//! cargo run --bin gen_dual_funding_corpus
//!
//! # Custom output dir:
//! cargo run --bin gen_dual_funding_corpus -- /path/to/corpus
//! ```
//!
//! # What is generated
//!
//! | Seed file           | Content |
//! |---------------------|---------|
//! | `seed_00..34`             | Random generator seeds (shape diversity) |
//! | `seed_valid_00..04`       | Real dual-funding: both sides contribute Bitcoin |
//! | `seed_abort_00..02`       | Full open → tx_abort path (handle_tx_abort) |
//! | `seed_shutdown_00..02`    | Full flow → shutdown (handle_peer_shutdown) |
//! | `seed_close_00..02`       | Full flow → closing_signed (handle_peer_closing_signed) |
//! | `seed_rbf_00..02`         | Full flow → tx_init_rbf + 2nd round (handle_peer_tx_init_rbf) |
//! | `seed_output_00..02`      | tx_add_output → interactivetx_add_output + psbt_open.c |
//! | `seed_remove_00..02`      | tx_remove_input + tx_remove_output → psbt_open.c remove paths |
//! | `seed_close_multi_00..02`    | 3-round closing_signed → fee-convergence loop in closingd.c |
//! | `seed_reestablish_00..02`    | channel_reestablish → handle_peer_reestablish (dualopend + closingd) |
//! | `seed_upfront_shutdown_00..02` | P2WPKH upfront_shutdown_script TLV → dualopend_wiregen.c |
//! | `seed_wrong_parity_00..02`   | odd serial_id → parity error path in interactivetx.c |
//!
//! All programs are type-correct and decode cleanly in `DualFundingScenario::run`.

use std::fs;
use std::path::Path;

use rand::SeedableRng;
use rand::rngs::SmallRng;
use smite_ir::operation::{AcceptChannel2Field, Operation};
use smite_ir::variable::VariableType;
use smite_ir::{Generator, InteractiveTxGenerator, ProgramBuilder};

/// Generate a program that sends `tx_abort` after `accept_channel2`.
///
/// Exercises CLN's `handle_tx_abort` in `dualopend.c`.
fn generate_tx_abort(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    // ── Keys ─────────────────────────────────────────────────────────────────
    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    // ── Channel parameters ────────────────────────────────────────────────────
    let chain_hash          = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id     = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate      = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // Zero contribution for abort path — CLN still processes open_channel2.
    let funding_sats        = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit          = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight   = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min            = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay       = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs  = b.append(Operation::LoadU16(30), &[]);
    let locktime            = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags       = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown    = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type        = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    // ── Phase 1: open_channel2 ────────────────────────────────────────────────
    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    // ── Phase 2: accept_channel2 → compute channel_id ────────────────────────
    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── Phase 3: tx_abort ─────────────────────────────────────────────────────
    let abort_data = b.append(Operation::LoadBytes(b"smite fuzzer abort".to_vec()), &[]);
    let tx_abort = b.append(Operation::BuildTxAbort, &[channel_id, abort_data]);
    b.append(Operation::SendMessage, &[tx_abort]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `shutdown` after tx_signatures.
///
/// Exercises CLN's `handle_peer_shutdown` in `dualopend.c`.
fn generate_shutdown(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    // ── Keys ─────────────────────────────────────────────────────────────────
    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    // ── Channel parameters ────────────────────────────────────────────────────
    let chain_hash          = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id     = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate      = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // Zero contribution for the shutdown seed.  The real dual-funding seeds
    // are in generate_valid() which uses LoadFundingUtxo* operations.
    let funding_sats        = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit          = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight   = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min            = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay       = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs  = b.append(Operation::LoadU16(30), &[]);
    let locktime            = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags       = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown    = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type        = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    // ── Phase 1: open_channel2 ────────────────────────────────────────────────
    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    // ── Phase 2: accept_channel2 → compute channel_id ────────────────────────
    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── Phase 3: tx_complete (zero contribution) ──────────────────────────────
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    // ── Phase 4: receive CLN's tx_signatures → extract real txid ─────────────
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);

    // ── Phase 5: send tx_signatures (empty witnesses — zero contribution) ─────
    let witnesses = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs   = b.append(Operation::BuildTxSignatures, &[channel_id, their_txid, witnesses]);
    b.append(Operation::SendMessage, &[tx_sigs]);

    // ── Phase 6: shutdown ↔ shutdown ─────────────────────────────────────────
    let scriptpubkey = b.append(Operation::LoadBytes(vec![]), &[]);
    let shutdown = b.append(Operation::BuildShutdown, &[channel_id, scriptpubkey]);
    b.append(Operation::SendMessage, &[shutdown]);
    // Wait for CLN's shutdown reply so we observe handle_peer_shutdown completing.
    let _peer_script = b.append(Operation::RecvShutdown, &[]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that drives shutdown + a closing_signed exchange.
///
/// Reaches `closingd.c::handle_peer_closing_signed` once the funding tx
/// confirms.  Even before lock-in this seed pre-loads CLN's parsing path
/// for `closing_signed` — useful for `dualopend_wiregen.c` / `peer_wire.c`
/// coverage of message type 39.
fn generate_close(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    // Identical key/parameter setup to the shutdown seed.
    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash          = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id     = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate      = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats        = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit          = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight   = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min            = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay       = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs  = b.append(Operation::LoadU16(30), &[]);
    let locktime            = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags       = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown    = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type        = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(Operation::BuildTxSignatures, &[channel_id, their_txid, witnesses]);
    b.append(Operation::SendMessage, &[tx_sigs]);

    // shutdown ↔ shutdown
    let scriptpubkey = b.append(Operation::LoadBytes(vec![]), &[]);
    let shutdown = b.append(Operation::BuildShutdown, &[channel_id, scriptpubkey]);
    b.append(Operation::SendMessage, &[shutdown]);
    let _peer_script = b.append(Operation::RecvShutdown, &[]);

    // closing_signed: propose a fee, send signature placeholder, then receive
    // CLN's counter-fee (drives handle_peer_closing_signed).
    let fee_satoshis = b.append(Operation::LoadAmount(500), &[]);
    let signature    = b.append(Operation::LoadBytes(vec![0u8; 64]), &[]); // executor falls back to a valid sig
    let closing_signed = b.append(
        Operation::BuildClosingSigned,
        &[channel_id, fee_satoshis, signature],
    );
    b.append(Operation::SendMessage, &[closing_signed]);
    let _peer_fee = b.append(Operation::RecvClosingSigned, &[]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that drives `tx_init_rbf` + a second interactive-tx round.
///
/// Reaches `dualopend.c::handle_peer_tx_init_rbf` (when CLN replies via
/// `tx_ack_rbf`) and re-enters `interactivetx.c` for the new round.
fn generate_rbf(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash          = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id     = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate      = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats        = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit          = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight   = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min            = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay       = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs  = b.append(Operation::LoadU16(30), &[]);
    let locktime            = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags       = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown    = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type        = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // First interactive-tx round: just tx_complete on both sides.
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(Operation::BuildTxSignatures, &[channel_id, their_txid, witnesses]);
    b.append(Operation::SendMessage, &[tx_sigs]);

    // RBF round: propose new feerate + funding-output contribution.
    let new_locktime    = b.append(Operation::LoadBlockHeight(0), &[]);
    let new_feerate     = b.append(Operation::LoadFeeratePerKw(2000), &[]);
    let new_contribution = b.append(Operation::LoadSignedAmount(0), &[]);
    // require_confirmed_inputs = false (0): normal RBF without confirmed-input requirement.
    let req_confirmed   = b.append(Operation::LoadU8(0), &[]);
    let tx_init_rbf = b.append(
        Operation::BuildTxInitRbf,
        &[channel_id, new_locktime, new_feerate, new_contribution, req_confirmed],
    );
    b.append(Operation::SendMessage, &[tx_init_rbf]);
    b.append(Operation::RecvTxAckRbf, &[]);

    // Re-enter interactive_tx for the RBF round.
    let tx_complete2 = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete2]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid2 = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses2  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs2    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid2, witnesses2],
    );
    b.append(Operation::SendMessage, &[tx_sigs2]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `tx_add_output` during interactive-tx.
///
/// Exercises `interactivetx_add_output()` in `interactivetx.c` and
/// `psbt_add_output_to_psbt()` in `psbt_open.c` — code paths that are
/// completely unreachable when we only send `tx_add_input`.
///
/// Sends a single P2WPKH change output (serial_id = 2, even = initiator),
/// then completes the interactive-tx round.
fn generate_with_output(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // Zero direct bitcoin contribution — we only send a change output.
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── tx_add_output: declare a P2WPKH change output ────────────────────────
    //
    // serial_id = 2 (even — initiator parity rule, BOLT 2).
    // Script: OP_0 <20-byte-hash> = 0x0014 followed by 20 zero bytes (22 bytes
    // total).  This is a syntactically valid P2WPKH scriptpubkey; CLN's
    // `is_known_scripttype` accepts it without needing a real hash.
    let serial_id_out = b.append(Operation::LoadAmount(2), &[]);
    let output_sats   = b.append(Operation::LoadAmount(100_000), &[]);
    let script = b.append(
        Operation::LoadBytes(
            // OP_0(0x00) + OP_PUSH20(0x14) + [0x00; 20]
            {
                let mut s = vec![0x00u8, 0x14];
                s.extend_from_slice(&[0x00u8; 20]);
                s
            },
        ),
        &[],
    );
    let tx_add_output = b.append(
        Operation::BuildTxAddOutput,
        &[channel_id, serial_id_out, output_sats, script],
    );
    b.append(Operation::SendMessage, &[tx_add_output]);

    // tx_complete — RecvTxComplete drains CLN's entire interactive-tx turn.
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that adds then removes inputs and outputs.
///
/// Exercises `interactivetx_remove_input()` and `interactivetx_remove_output()`
/// in `interactivetx.c`, and `psbt_remove_input_from_psbt()` /
/// `psbt_remove_output_from_psbt()` in `psbt_open.c`.
///
/// Flow: tx_add_input → tx_remove_input → tx_add_output → tx_remove_output
/// → tx_complete (net-zero contribution).
fn generate_remove(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // Declare 1M sat contribution so CLN expects our tx_add_input to be valid.
    let funding_sats       = b.append(Operation::LoadAmount(1_000_000), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── tx_add_input → tx_remove_input ───────────────────────────────────────
    //
    // Send a real input (serial_id = 0, even = initiator) backed by a context
    // UTXO so CLN's prevtx validation passes.  Immediately remove it — the net
    // result is zero contribution from our side, exercising the remove path.
    let prevtx          = b.append(Operation::LoadFundingUtxoRawTx(0), &[]);
    let prevtx_vout     = b.append(Operation::LoadFundingUtxoVout(0), &[]);
    let serial_id_in    = b.append(Operation::LoadAmount(0), &[]);
    let sequence        = b.append(Operation::LoadBlockHeight(0xffff_fffd), &[]);
    let tx_add_input = b.append(
        Operation::BuildTxAddInput,
        &[channel_id, serial_id_in, prevtx, prevtx_vout, sequence],
    );
    b.append(Operation::SendMessage, &[tx_add_input]);

    // tx_remove_input: reference the same serial_id we just added.
    let tx_remove_input = b.append(
        Operation::BuildTxRemoveInput,
        &[channel_id, serial_id_in],
    );
    b.append(Operation::SendMessage, &[tx_remove_input]);

    // ── tx_add_output → tx_remove_output ─────────────────────────────────────
    let serial_id_out = b.append(Operation::LoadAmount(2), &[]);
    let output_sats   = b.append(Operation::LoadAmount(100_000), &[]);
    let script = b.append(
        Operation::LoadBytes({
            let mut s = vec![0x00u8, 0x14];
            s.extend_from_slice(&[0x00u8; 20]);
            s
        }),
        &[],
    );
    let tx_add_output = b.append(
        Operation::BuildTxAddOutput,
        &[channel_id, serial_id_out, output_sats, script],
    );
    b.append(Operation::SendMessage, &[tx_add_output]);

    let tx_remove_output = b.append(
        Operation::BuildTxRemoveOutput,
        &[channel_id, serial_id_out],
    );
    b.append(Operation::SendMessage, &[tx_remove_output]);

    // tx_complete — CLN finishes its turn; we have zero net contribution.
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program with multiple `closing_signed` rounds.
///
/// Exercises the fee-negotiation convergence loop in `closingd.c`:
/// `handle_peer_closing_signed` is called once per round; CLN's
/// `closing_fee_negotiation` logic (binary search / accept-in-range) is
/// exercised with escalating fee proposals.
///
/// Three rounds: 300 → 600 → 1_200 sat fee proposals.
fn generate_close_multi(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // tx_complete (zero contribution).
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    // shutdown ↔ shutdown.
    let scriptpubkey = b.append(Operation::LoadBytes(vec![]), &[]);
    let shutdown = b.append(Operation::BuildShutdown, &[channel_id, scriptpubkey]);
    b.append(Operation::SendMessage, &[shutdown]);
    let _peer_script = b.append(Operation::RecvShutdown, &[]);

    // ── closing_signed: three escalating fee rounds ───────────────────────────
    //
    // CLN's closing_fee_negotiation (closingd.c) does a binary search / accept-
    // in-range check.  Sending fees that bracket CLN's acceptable range forces
    // the convergence loop to execute multiple iterations.
    //
    // Round 1 — low offer; CLN will counter-propose a higher fee.
    let fee1 = b.append(Operation::LoadAmount(300), &[]);
    let sig1  = b.append(Operation::LoadBytes(vec![0u8; 64]), &[]);
    let cs1   = b.append(Operation::BuildClosingSigned, &[channel_id, fee1, sig1]);
    b.append(Operation::SendMessage, &[cs1]);
    let _peer_fee1 = b.append(Operation::RecvClosingSigned, &[]);

    // Round 2 — mid offer; CLN narrows its range.
    let fee2 = b.append(Operation::LoadAmount(600), &[]);
    let sig2  = b.append(Operation::LoadBytes(vec![0u8; 64]), &[]);
    let cs2   = b.append(Operation::BuildClosingSigned, &[channel_id, fee2, sig2]);
    b.append(Operation::SendMessage, &[cs2]);
    let _peer_fee2 = b.append(Operation::RecvClosingSigned, &[]);

    // Round 3 — higher offer; should be within CLN's acceptable range.
    let fee3 = b.append(Operation::LoadAmount(1_200), &[]);
    let sig3  = b.append(Operation::LoadBytes(vec![0u8; 64]), &[]);
    let cs3   = b.append(Operation::BuildClosingSigned, &[channel_id, fee3, sig3]);
    b.append(Operation::SendMessage, &[cs3]);
    let _peer_fee3 = b.append(Operation::RecvClosingSigned, &[]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `channel_reestablish` after `tx_signatures`.
///
/// Exercises `handle_peer_reestablish` in `dualopend.c`.  Values are
/// semantically correct for a channel that has exchanged exactly one
/// commitment transaction (number 0) but no revocations:
///
/// - `next_commitment_number = 1`  (expecting peer's commitment #1 next)
/// - `next_revocation_number = 0`  (no commitments revoked)
/// - `your_last_per_commitment_secret = [0; 32]`  (no secrets received)
/// - `my_current_per_commitment_point = first_per_commitment_point`
///
/// CLN will respond with its own `channel_reestablish` which `RecvChannelReestablish`
/// drains so the connection stays in sync.
fn generate_reestablish(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // tx_complete → tx_signatures (zero contribution).
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    // ── channel_reestablish ───────────────────────────────────────────────────
    //
    // Correct BOLT 1 values for a fresh channel:
    //   next_commitment_number  = 1 (have received commitment #0)
    //   next_revocation_number  = 0 (no revocations issued)
    //   your_last_per_commitment_secret = [0; 32] (no secrets received)
    //   my_current_per_commitment_point = first_per_commitment_point
    let next_commit_num  = b.append(Operation::LoadAmount(1), &[]);
    let next_revoke_num  = b.append(Operation::LoadAmount(0), &[]);
    let secret           = b.append(Operation::LoadBytes(vec![0u8; 32]), &[]);
    let reestablish_msg  = b.append(
        Operation::BuildChannelReestablish,
        &[channel_id, next_commit_num, next_revoke_num, secret, first_per_commitment_point],
    );
    b.append(Operation::SendMessage, &[reestablish_msg]);
    b.append(Operation::RecvChannelReestablish, &[]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `open_channel2` with a real P2WPKH
/// `upfront_shutdown_script`.
///
/// Exercises the TLV encode/decode path for `upfront_shutdown_script` in
/// `dualopend_wiregen.c`.  The script is derived from `funding_pubkey` via
/// `ComputeP2WPKHScript` — not a hardcoded byte vector — so it is a
/// semantically valid scriptpubkey that CLN's `is_known_scripttype` accepts.
fn generate_upfront_shutdown(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    // ── Key-derived P2WPKH upfront_shutdown_script ────────────────────────────
    //
    // ComputeP2WPKHScript(funding_pubkey) → OP_0 OP_PUSH20 HASH160(pubkey)
    // This is a real scriptpubkey (not hardcoded bytes) that CLN accepts
    // as a valid standard script type.
    let upfront_shutdown = b.append(Operation::ComputeP2WPKHScript, &[funding_pubkey]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // tx_complete → tx_signatures (zero contribution).
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `tx_add_input` with an odd (wrong-parity)
/// serial_id.
///
/// BOLT 2: the initiator MUST use **even** serial IDs.  Sending serial_id = 1
/// (odd) triggers CLN's `check_tx_add_input` parity validation in
/// `interactivetx.c`, causing CLN to send an error and exercising the
/// error-handling branch.  This is a deliberate protocol violation seed —
/// AFL++ cannot discover this path through mutation alone because valid seeds
/// always use even serial IDs.
fn generate_wrong_parity(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // Declare 1M sat contribution so CLN expects an input from us.
    let funding_sats       = b.append(Operation::LoadAmount(1_000_000), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── tx_add_input with ODD serial_id = 1 (wrong parity for initiator) ─────
    //
    // BOLT 2 §6.2: "The initiator MUST use even serial_ids."
    // CLN's `check_tx_add_input` in `interactivetx.c` rejects this and sends
    // an error — exercising the validation error branch.
    let prevtx       = b.append(Operation::LoadFundingUtxoRawTx(0), &[]);
    let prevtx_vout  = b.append(Operation::LoadFundingUtxoVout(0), &[]);
    let serial_id_odd = b.append(Operation::LoadAmount(1), &[]); // ODD — wrong parity
    let sequence     = b.append(Operation::LoadBlockHeight(0xffff_fffd), &[]);
    let tx_add_input = b.append(
        Operation::BuildTxAddInput,
        &[channel_id, serial_id_odd, prevtx, prevtx_vout, sequence],
    );
    b.append(Operation::SendMessage, &[tx_add_input]);
    // CLN will respond with an error; RecvTxAbort drains it gracefully.
    b.append(Operation::RecvTxAbort, &[]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program that sends `tx_init_rbf` with `require_confirmed_inputs = true`.
///
/// Exercises the `require_confirmed_inputs` TLV branch in `dualopend_wiregen.c`
/// and the corresponding validation in `handle_peer_tx_init_rbf` in `dualopend.c`.
///
/// BOLT 2: when set, the peer must only add inputs confirmed on-chain.
/// CLN checks `require_confirmed_inputs` in its TLV handling — this seed forces
/// that branch to execute (vs. the normal path where it is always false).
fn generate_rbf_confirmed(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // tx_complete → tx_signatures (zero contribution).
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    // ── tx_init_rbf with require_confirmed_inputs = true ─────────────────────
    //
    // LoadU8(1) → nonzero → require_confirmed_inputs = true in the TLV.
    // This exercises the TLV serialisation branch in dualopend_wiregen.c and
    // the validation check in handle_peer_tx_init_rbf in dualopend.c.
    let new_locktime     = b.append(Operation::LoadBlockHeight(0), &[]);
    let new_feerate      = b.append(Operation::LoadFeeratePerKw(3000), &[]);
    let new_contribution = b.append(Operation::LoadSignedAmount(0), &[]);
    let req_confirmed    = b.append(Operation::LoadU8(1), &[]); // require_confirmed_inputs = TRUE
    let tx_init_rbf = b.append(
        Operation::BuildTxInitRbf,
        &[channel_id, new_locktime, new_feerate, new_contribution, req_confirmed],
    );
    b.append(Operation::SendMessage, &[tx_init_rbf]);
    b.append(Operation::RecvTxAckRbf, &[]);

    // RBF interactive-tx round (empty: just tx_complete).
    let tx_complete2 = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete2]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid2 = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses2  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs2    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid2, witnesses2],
    );
    b.append(Operation::SendMessage, &[tx_sigs2]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program using `channel_type = [0x10, 0x00]` (static_remotekey only,
/// no anchors).
///
/// Exercises the `channel_type` TLV negotiation branch in `dualopend.c` for a
/// non-anchor channel.  Alongside the default `[0x40, 0x10, 0x00]` (anchors +
/// static_remotekey) seeds, this ensures both branches of CLN's channel-type
/// validation are covered:
///
///   bit 12 (0x10, 0x00) = option_static_remotekey
///   bit 22 (0x40)       = option_anchors_zero_fee_htlc_tx
///
/// `[0x10, 0x00]` requests static_remotekey WITHOUT anchors — a valid feature
/// vector that CLN accepts when its policy permits non-anchor channels.
fn generate_channel_type_static_only(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(0), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    // static_remotekey only: bit 12 = 0x1000, encoded as little-endian [0x10, 0x00].
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    // CLN may reject or accept this channel type — RecvAcceptChannel2 drains
    // the response (RecvTxAbort is handled upstream if CLN rejects).
    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a program with varying `funding_output_contribution` signs in RBF.
///
/// Exercises CLN's `check_balances` branches in `dualopend.c`:
///   - Positive: fuzzer contributes +500_000 sats to the new funding output.
///   - Negative: fuzzer withdraws −500_000 sats (reduces funding output).
///   - Zero:     fuzzer makes no change to its contribution.
///
/// Each variant covers a different branch of the contribution-validation logic.
/// AFL++ mutation alone is unlikely to discover negative signed amounts because
/// all valid seeds use 0 or positive values.
fn generate_contribution_variants(rng: &mut impl rand::Rng, contribution_sats: i64) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    let chain_hash         = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id    = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate    = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let funding_sats       = b.append(Operation::LoadAmount(1_000_000), &[]);
    let dust_limit         = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight  = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min           = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay      = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let locktime           = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags      = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown   = b.append(Operation::LoadBytes(vec![]), &[]);
    let channel_type       = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // First tx round (minimal: just tx_complete).
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    // ── tx_init_rbf with varied funding_output_contribution ───────────────────
    //
    // The `contribution_sats` parameter is positive/negative/zero to drive
    // different branches in CLN's check_balances().
    let new_locktime     = b.append(Operation::LoadBlockHeight(0), &[]);
    let new_feerate      = b.append(Operation::LoadFeeratePerKw(2500), &[]);
    let new_contribution = b.append(Operation::LoadSignedAmount(contribution_sats), &[]);
    let req_confirmed    = b.append(Operation::LoadU8(0), &[]);
    let tx_init_rbf = b.append(
        Operation::BuildTxInitRbf,
        &[channel_id, new_locktime, new_feerate, new_contribution, req_confirmed],
    );
    b.append(Operation::SendMessage, &[tx_init_rbf]);
    b.append(Operation::RecvTxAckRbf, &[]);

    let tx_complete2 = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete2]);
    b.append(Operation::RecvTxComplete, &[]);

    let their_txid2 = b.append(Operation::RecvTxSignatures, &[]);
    let witnesses2  = b.append(Operation::LoadBytes(vec![]), &[]);
    let tx_sigs2    = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid2, witnesses2],
    );
    b.append(Operation::SendMessage, &[tx_sigs2]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

fn generate(seed: u64) -> Vec<u8> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    InteractiveTxGenerator.generate(&mut builder, &mut rng);
    let program = builder.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

/// Generate a BOLT 2-compliant real dual-funding program.
///
/// Both the fuzzer and CLN contribute real Bitcoin:
///
/// - Fuzzer side: `funding_satoshis = 1_000_000` sats (our declared contribution).
///   We send a real `tx_add_input` referencing our UTXO from context
///   (`LoadFundingUtxoRawTx(0)`, `LoadFundingUtxoVout(0)`).
///
/// - CLN side: `--funder-policy=available` causes CLN to contribute from its
///   own wallet — it sends `tx_add_input` + `tx_add_output` messages, then
///   `tx_complete`.  `RecvTxComplete` drains and records CLN's contributions
///   so `ComputeFundingWitness` can include them in the BIP 143 preimage.
///
/// - Signing: `ComputeFundingWitness` computes the BIP 143 P2WPKH sighash
///   over ALL inputs/outputs (both ours and CLN's), signs our input with our
///   private key (from `ProgramContext.funding_utxos[0]`), and encodes the
///   real DER+SIGHASH_ALL witness.
///
/// - txid: `RecvTxSignatures` receives CLN's tx_signatures and extracts the
///   real txid of the negotiated funding transaction.  We echo it back in our
///   `tx_signatures` so CLN's `handle_tx_sigs` validates against it.
///
/// This seed exercises the full dual-funding code path in `dualopend.c`:
///   `handle_tx_sigs` ← called with a valid txid and real P2WPKH witness.
fn generate_valid(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut b = ProgramBuilder::new();

    // ── Public keys ───────────────────────────────────────────────────────────
    //
    // CLN recomputes temporary_channel_id from the basepoints in open_channel2
    // and rejects if it doesn't match.  Formula (CLN common/channel_id.c):
    //   temp_channel_id = SHA256(zeros[33] || revocation_basepoint[33])
    let funding_pubkey              = b.generate_fresh(VariableType::Point, rng);
    let revocation_basepoint        = b.generate_fresh(VariableType::Point, rng);
    let payment_basepoint           = b.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint   = b.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint              = b.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point  = b.generate_fresh(VariableType::Point, rng);
    let second_per_commitment_point = b.generate_fresh(VariableType::Point, rng);

    // ── Channel parameters (BOLT 2 compliant) ─────────────────────────────────
    let chain_hash          = b.append(Operation::LoadChainHashFromContext, &[]);
    let temp_channel_id     = b.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
    let funding_feerate     = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    let commit_feerate      = b.append(Operation::LoadFeeratePerKw(1000), &[]);
    // We declare 1,000,000 sats as our contribution.  We back this up with a
    // real tx_add_input from the fuzzer UTXO (loaded from context at runtime).
    let funding_sats        = b.append(Operation::LoadAmount(1_000_000), &[]);
    let dust_limit          = b.append(Operation::LoadAmount(546), &[]);
    let max_htlc_inflight   = b.append(Operation::LoadAmount(990_000_000), &[]);
    let htlc_min            = b.append(Operation::LoadAmount(1), &[]);
    let to_self_delay       = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs  = b.append(Operation::LoadU16(30), &[]);
    let locktime            = b.append(Operation::LoadBlockHeight(0), &[]);
    let channel_flags       = b.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown    = b.append(Operation::LoadBytes(vec![]), &[]);
    // channel_type: option_static_remotekey (bit 12) + option_anchors_zero_fee_htlc_tx (bit 22)
    let channel_type        = b.append(Operation::LoadFeatures(vec![0x40, 0x10, 0x00]), &[]);

    // ── Phase 1: open_channel2 ────────────────────────────────────────────────
    let open_ch2 = b.append(Operation::BuildOpenChannel2, &[
        chain_hash, temp_channel_id,
        funding_feerate, commit_feerate,
        funding_sats, dust_limit, max_htlc_inflight, htlc_min,
        to_self_delay, max_accepted_htlcs, locktime,
        funding_pubkey, revocation_basepoint, payment_basepoint,
        delayed_payment_basepoint, htlc_basepoint,
        first_per_commitment_point, second_per_commitment_point,
        channel_flags, upfront_shutdown, channel_type,
    ]);
    b.append(Operation::SendMessage, &[open_ch2]);

    // ── Phase 2: accept_channel2 → compute full channel_id ───────────────────
    let accept = b.append(Operation::RecvAcceptChannel2, &[]);
    let _their_rev = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[accept],
    );
    // CLN keeps state->channel_id = temporary_channel_id throughout the entire
    // interactive-tx phase (tx_add_input, tx_add_output, tx_complete, tx_abort,
    // tx_signatures).  Using ComputeChannelIdV2 (SHA256 of sorted rev basepoints)
    // causes check_channel_id() in dualopend.c to fail BEFORE any interactivetx.c
    // function is entered.
    let channel_id = temp_channel_id;

    // ── Phase 3: tx_add_input with our real UTXO ─────────────────────────────
    //
    // LoadFundingUtxoRawTx(0) returns ProgramContext.funding_utxos[0].raw_tx —
    // the serialized previous transaction.  This is the `prevtx` field that
    // CLN validates (it decodes the tx and checks the output exists).
    //
    // LoadFundingUtxoVout(0) returns the output index within that tx.
    // Serial ID 0 = even (initiator rule, BOLT 2).
    let prevtx          = b.append(Operation::LoadFundingUtxoRawTx(0), &[]);
    let prevtx_vout     = b.append(Operation::LoadFundingUtxoVout(0), &[]);
    let serial_id_input = b.append(Operation::LoadAmount(0), &[]); // serial_id = 0 (even)
    let sequence        = b.append(Operation::LoadBlockHeight(0xffff_fffd), &[]); // RBF-enabled
    let tx_add_input = b.append(
        Operation::BuildTxAddInput,
        &[channel_id, serial_id_input, prevtx, prevtx_vout, sequence],
    );
    b.append(Operation::SendMessage, &[tx_add_input]);
    // Receive CLN's corresponding interactive-tx message (CLN may send
    // tx_add_input or tx_add_output in response; RecvTxAddInput drains one).
    b.append(Operation::RecvTxAddInput, &[]);

    // ── Phase 4: tx_complete (we are done adding) ─────────────────────────────
    //
    // RecvTxComplete drains CLN's remaining interactive-tx contributions
    // (tx_add_input / tx_add_output for CLN's wallet inputs/outputs) AND
    // records them in the executor's itx_inputs / itx_outputs lists so that
    // ComputeFundingWitness can include them in the BIP 143 preimage.
    let tx_complete = b.append(Operation::BuildTxComplete, &[channel_id]);
    b.append(Operation::SendMessage, &[tx_complete]);
    b.append(Operation::RecvTxComplete, &[]);

    // ── Phase 5: receive CLN's tx_signatures → extract real txid ─────────────
    //
    // BOLT 2: the party with the lower funding_pubkey sends tx_signatures FIRST.
    // If CLN has the lower pubkey, CLN sends its tx_signatures here and we
    // extract the real txid of the negotiated funding transaction.
    // If we have the lower pubkey, RecvTxSignatures returns zeros — we still
    // send tx_signatures, triggering handle_tx_sigs for validation.
    let their_txid = b.append(Operation::RecvTxSignatures, &[]);

    // ── Phase 6: compute real BIP 143 P2WPKH witness ─────────────────────────
    //
    // ComputeFundingWitness uses the executor's tracked inputs/outputs (both
    // ours from BuildTxAddInput and CLN's from RecvTxComplete draining) to:
    //   1. Sort all inputs/outputs by serial_id.
    //   2. Compute the BIP 143 sighash for our UTXO input.
    //   3. Sign with our private key (from ProgramContext.funding_utxos[0]).
    //   4. Encode as DER+SIGHASH_ALL with compressed pubkey witness.
    let witnesses = b.append(Operation::ComputeFundingWitness, &[]);

    // ── Phase 7: tx_signatures with real txid + real witness ─────────────────
    let tx_sigs = b.append(
        Operation::BuildTxSignatures,
        &[channel_id, their_txid, witnesses],
    );
    b.append(Operation::SendMessage, &[tx_sigs]);

    let program = b.build();
    postcard::to_allocvec(&program).expect("serialization never fails")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args.get(1).map(String::as_str).unwrap_or("corpus/dual-funding");

    fs::create_dir_all(out_dir)
        .unwrap_or_else(|e| panic!("cannot create output directory '{out_dir}': {e}"));

    let seeds: &[(u64, &str)] = &[
        // Seed 0: no negotiation rounds (open → tx_complete → tx_sigs).
        (0x0000_0000_0000_0000, "seed_00"),
        (0x0000_0000_0000_0003, "seed_01"),
        (0x0000_0000_0000_0005, "seed_02"),
        (0x0000_0000_0000_000B, "seed_03"),
        (0x0000_0000_0000_000D, "seed_04"),
        (0x0000_0000_0000_0011, "seed_05"),
        (0x0000_0000_0000_0013, "seed_06"),
        (0x0000_0000_0000_001D, "seed_07"),
        (0x0000_0000_0000_001F, "seed_08"),
        (0x0000_0000_0000_0025, "seed_09"),
        (0x0000_0000_0000_0029, "seed_10"),
        (0x0000_0000_0000_002B, "seed_11"),
        (0x0000_0000_0000_002F, "seed_12"),
        (0x0000_0000_0000_0035, "seed_13"),
        (0x0000_0000_0000_003B, "seed_14"),
        (0x0000_0000_0000_003D, "seed_15"),
        (0xDEAD_BEEF_CAFE_0001, "seed_16"),
        (0xDEAD_BEEF_CAFE_0002, "seed_17"),
        (0xDEAD_BEEF_CAFE_0003, "seed_18"),
        (0xDEAD_BEEF_CAFE_0004, "seed_19"),
        (0xDEAD_BEEF_CAFE_0005, "seed_20"),
        (0xDEAD_BEEF_CAFE_0006, "seed_21"),
        (0xDEAD_BEEF_CAFE_0007, "seed_22"),
        (0xDEAD_BEEF_CAFE_0008, "seed_23"),
        (0xDEAD_BEEF_CAFE_0009, "seed_24"),
        (0xDEAD_BEEF_CAFE_000A, "seed_25"),
        (0xDEAD_BEEF_CAFE_000B, "seed_26"),
        (0xDEAD_BEEF_CAFE_000C, "seed_27"),
        (0xDEAD_BEEF_CAFE_000D, "seed_28"),
        (0xDEAD_BEEF_CAFE_000E, "seed_29"),
        (0xDEAD_BEEF_CAFE_000F, "seed_30"),
        (0xDEAD_BEEF_CAFE_0010, "seed_31"),
        (0x6c69676874_000001,   "seed_32"),
        (0x6c69676874_000002,   "seed_33"),
        (0x6c69676874_000003,   "seed_34"),
    ];

    let mut total_bytes = 0usize;
    let mut count = 0usize;

    for (seed, name) in seeds {
        let bytes = generate(*seed);
        let path = Path::new(out_dir).join(name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!("  wrote {} ({} bytes)", path.display(), bytes.len());
    }

    // ── Real dual-funding seeds ───────────────────────────────────────────────
    //
    // BOTH the fuzzer and CLN contribute real Bitcoin:
    //   - Fuzzer: 1M sats via LoadFundingUtxo* + BuildTxAddInput
    //   - CLN: wallet funds via --funder-policy=available
    //   - Witness: BIP 143 P2WPKH signed by ComputeFundingWitness
    //   - txid: real txid from RecvTxSignatures
    //
    // These seeds are the primary path for exercising handle_tx_sigs correctly.
    for i in 0..5u64 {
        let name = format!("seed_valid_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xB0_1710_CAFE_0000 + i);
        let bytes = generate_valid(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [real dual-fund: 1M sats + BIP143 witness]",
            path.display(), bytes.len()
        );
    }

    // ── tx_abort seeds ────────────────────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_abort_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xAB0E_CAF0_0000 + i);
        let bytes = generate_tx_abort(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [tx_abort → handle_tx_abort]",
            path.display(), bytes.len()
        );
    }

    // ── shutdown seeds ────────────────────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_shutdown_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x5D00_0000_0000 + i);
        let bytes = generate_shutdown(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [shutdown → handle_peer_shutdown]",
            path.display(), bytes.len()
        );
    }

    // ── closing_signed seeds ─────────────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_close_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xC105_E000_0000 + i);
        let bytes = generate_close(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [closing_signed → handle_peer_closing_signed]",
            path.display(), bytes.len()
        );
    }

    // ── tx_init_rbf seeds ────────────────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_rbf_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x12B_F000_0000 + i);
        let bytes = generate_rbf(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [tx_init_rbf → handle_peer_tx_init_rbf]",
            path.display(), bytes.len()
        );
    }

    // ── tx_add_output seeds ──────────────────────────────────────────────────
    // Exercises interactivetx_add_output() + psbt_add_output_to_psbt() —
    // both are unreachable from any seed that only sends tx_add_input.
    for i in 0..3u64 {
        let name = format!("seed_output_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x0A_DD_0000_0000 + i);
        let bytes = generate_with_output(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [tx_add_output → interactivetx_add_output + psbt_open]",
            path.display(), bytes.len()
        );
    }

    // ── tx_remove_input/output seeds ─────────────────────────────────────────
    // Exercises interactivetx_remove_input/output() + psbt_remove_*_from_psbt()
    // — the only seeds that reach the remove handlers in interactivetx.c.
    for i in 0..3u64 {
        let name = format!("seed_remove_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x12E0_0000_0000 + i);
        let bytes = generate_remove(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [tx_remove_input+output → interactivetx_remove_*]",
            path.display(), bytes.len()
        );
    }

    // ── multi-round closing_signed seeds ─────────────────────────────────────
    // Exercises the fee-convergence loop in closingd.c::closing_fee_negotiation.
    // A single-round seed only enters handle_peer_closing_signed once; this
    // seed sends 3 rounds with escalating fees to drive convergence branches.
    for i in 0..3u64 {
        let name = format!("seed_close_multi_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xC105_E_0001_0000 + i);
        let bytes = generate_close_multi(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [3-round closing_signed → fee convergence in closingd.c]",
            path.display(), bytes.len()
        );
    }

    // ── channel_reestablish seeds ─────────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_reestablish_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xBE_57_AB_0000_0000 + i);
        let bytes = generate_reestablish(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [channel_reestablish → handle_peer_reestablish]",
            path.display(), bytes.len()
        );
    }

    // ── upfront_shutdown_script seeds ────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_upfront_shutdown_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x5D_0B_0000_0000 + i);
        let bytes = generate_upfront_shutdown(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [P2WPKH upfront_shutdown_script TLV → dualopend_wiregen.c]",
            path.display(), bytes.len()
        );
    }

    // ── wrong-parity serial_id seeds ─────────────────────────────────────────
    for i in 0..3u64 {
        let name = format!("seed_wrong_parity_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xBAD_0000_0000_0000 + i);
        let bytes = generate_wrong_parity(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [odd serial_id → check_tx_add_input error path]",
            path.display(), bytes.len()
        );
    }

    // ── require_confirmed_inputs=true seeds ──────────────────────────────────
    // Exercises the TLV flag branch in dualopend_wiregen.c + handle_peer_tx_init_rbf.
    // Without this seed AFL++ can't reach the `require_confirmed_inputs` TLV
    // encode path because every other seed sends 0 (false).
    for i in 0..3u64 {
        let name = format!("seed_rbf_confirmed_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0xCF00_0000_0000_0000 + i);
        let bytes = generate_rbf_confirmed(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [require_confirmed_inputs=true TLV → dualopend_wiregen.c]",
            path.display(), bytes.len()
        );
    }

    // ── static_remotekey-only channel_type seeds ─────────────────────────────
    // channel_type = [0x10, 0x00] (bit 12 only — static_remotekey, no anchors).
    // Exercises the channel-type TLV negotiation branch for non-anchor channels.
    for i in 0..3u64 {
        let name = format!("seed_channel_type_static_{i:02}");
        let mut rng = SmallRng::seed_from_u64(0x5718_0000_0000_0000 + i);
        let bytes = generate_channel_type_static_only(&mut rng);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [channel_type=[0x10,0x00] static_remotekey → dualopend.c type negotiation]",
            path.display(), bytes.len()
        );
    }

    // ── funding_output_contribution sign variants ─────────────────────────────
    // Three sub-variants: positive (+500_000), negative (−500_000), zero (0).
    // Each drives a different branch in CLN's check_balances() in dualopend.c.
    let contribution_cases: &[(i64, &str)] = &[
        ( 500_000, "pos"),   // +500_000 sats: increase contribution
        (-500_000, "neg"),   // -500_000 sats: decrease contribution (withdrawal)
        (       0, "zero"),  //        0 sats: no change
    ];
    for (i, &(contrib, label)) in contribution_cases.iter().enumerate() {
        let name = format!("seed_contribution_{label}");
        let mut rng = SmallRng::seed_from_u64(0xC0_7B_0000_0000_0000 + i as u64);
        let bytes = generate_contribution_variants(&mut rng, contrib);
        let path = Path::new(out_dir).join(&name);
        fs::write(&path, &bytes)
            .unwrap_or_else(|e| panic!("cannot write '{name}': {e}"));
        total_bytes += bytes.len();
        count += 1;
        println!(
            "  wrote {} ({} bytes) [funding_output_contribution={contrib} → check_balances branch]",
            path.display(), bytes.len()
        );
    }

    println!();
    println!(
        "Generated {count} seed files → '{out_dir}' ({total_bytes} bytes total)",
    );
    println!("  - 35 random seeds                 : fuzz open_channel2 validation");
    println!("  - 5 valid seeds                   : REAL dual-fund (1M sats fuzzer + BIP 143 P2WPKH witness)");
    println!("  - 3 abort seeds                   : hit handle_tx_abort in dualopend.c");
    println!("  - 3 shutdown seeds                : hit handle_peer_shutdown in dualopend.c");
    println!("  - 3 close seeds                   : hit handle_peer_closing_signed in closingd.c");
    println!("  - 3 rbf seeds                     : hit handle_peer_tx_init_rbf in dualopend.c");
    println!("  - 3 output seeds                  : hit interactivetx_add_output + psbt_open.c output path");
    println!("  - 3 remove seeds                  : hit interactivetx_remove_input/output + psbt_open.c remove paths");
    println!("  - 3 close_multi seeds             : hit fee-convergence loop in closingd.c (3 rounds)");
    println!("  - 3 reestablish seeds             : hit handle_peer_reestablish in dualopend.c + closingd.c");
    println!("  - 3 upfront_shutdown seeds        : hit upfront_shutdown_script TLV in dualopend_wiregen.c");
    println!("  - 3 wrong_parity seeds            : hit serial_id parity error in interactivetx.c");
    println!("  - 3 rbf_confirmed seeds           : hit require_confirmed_inputs=true TLV in dualopend_wiregen.c");
    println!("  - 3 channel_type_static seeds     : hit static_remotekey-only channel_type negotiation");
    println!("  - 3 contribution variant seeds    : hit +/−/0 funding_output_contribution in check_balances");
    println!();
    println!("NOTE: seed_valid_* programs use LoadFundingUtxo* operations that");
    println!("      require ProgramContext.funding_utxos to be populated at runtime.");
    println!("      The ClnTarget::setup_fuzzer_wallet() method handles this during");
    println!("      scenario setup (before the Nyx snapshot is taken).");
    println!();
    println!("Run the fuzzer with:");
    println!(
        "  cargo afl fuzz -i {out_dir} -o findings/cln target/release/cln_dual_funding"
    );
}
