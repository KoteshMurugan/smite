//! Generator for the BOLT 2 dual-funding interactive-transaction protocol.
//!
//! # Protocol flow (normal)
//!
//! ```text
//! initiator                       responder
//!    |                               |
//!    |--- open_channel2 (type 64) -->|
//!    |<-- accept_channel2 (65)  -----|
//!    |                               |
//!    |  ← N rounds of tx_add_input / tx_add_output interleaved →
//!    |                               |
//!    |--- tx_complete (70) -------->|
//!    |<-- tx_complete (70)  --------|
//!    |                               |
//!    |--- tx_signatures (71) ------>|
//!    |--- shutdown (38) ----------->|   ← optional: tests handle_peer_shutdown
//! ```
//!
//! # Protocol flow (abort)
//!
//! ```text
//! initiator                       responder
//!    |--- open_channel2 (64) ------>|
//!    |<-- accept_channel2 (65) -----|
//!    |--- tx_abort (74) ----------->|   ← tests handle_tx_abort in dualopend.c
//! ```
//!
//! # Serial-ID parity rule (BOLT 2)
//!
//! The **initiator** (us) MUST use **even** serial IDs; the **responder** MUST
//! use **odd** serial IDs.  This generator always emits even serial IDs for
//! our own `tx_add_input` / `tx_add_output` messages.
//!
//! # Convergence
//!
//! Both sides must send `tx_complete` to finish negotiation.  The generator:
//!   1. Emits 0–`MAX_ROUNDS` pairs of (send tx_add_*, recv tx_add_*).
//!   2. Either sends `tx_abort` (20% chance — hits `handle_tx_abort`) OR:
//!   3. Sends `tx_complete` to signal we are done adding.
//!   4. Receives `tx_complete` (peer may also send `tx_abort`).
//!   5. Computes BIP 143 witnesses OR uses random bytes (50/50).
//!   6. Sends `tx_signatures` with real or random witnesses.
//!   7. Optionally sends `shutdown` (20% chance — hits `handle_peer_shutdown`).
//!
//! # Real dual-funding (UTXO-backed inputs)
//!
//! When the program context contains `funding_utxos`, the generator emits
//! `LoadFundingUtxo*` operations instead of random bytes for tx_add_input
//! data.  This makes the fuzzer a genuine dual-funder: it contributes a real
//! UTXO and signs it with BIP 143 P2WPKH.  AFL++ then mutates from this valid
//! baseline to explore the full interactive-tx validation code in dualopend.c.

use rand::{Rng, RngExt};

use super::interactive_tx_setup::InteractiveTxSetup;
use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::Operation;
use crate::VariableType;

/// Maximum number of interactive-tx negotiation rounds before tx_complete.
const MAX_ROUNDS: usize = 5;

/// Generates a complete BOLT 2 dual-funding channel-open + interactive-tx
/// negotiation sequence.
///
/// The generator produces type-correct IR programs that exercise:
///
/// 1. `open_channel2` / `accept_channel2` handshake.
/// 2. 0–[`MAX_ROUNDS`] rounds of tx_add_input / tx_add_output negotiation.
/// 3. `tx_complete` exchange (or early `tx_abort` — 20%).
/// 4. `tx_signatures` with BIP 143 real witness OR random witness.
/// 5. Optional `shutdown` (20% chance).
pub struct InteractiveTxGenerator;

impl Generator for InteractiveTxGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // ── Phases 1 & 2: open_channel2 / accept_channel2 handshake ─────────
        //
        // Delegated to the InteractiveTxSetup primitive so future flows
        // (splice, RBF-restart, channel_ready) can share this prefix.
        let setup = InteractiveTxSetup.emit(builder, rng);

        // CLN's dualopend keeps state->channel_id == temporary_channel_id
        // throughout the interactive-tx phase (until tx_signatures).  Using
        // the derived ComputeChannelIdV2 here would fail check_channel_id()
        // before interactivetx.c is ever called.
        let channel_id = setup.temporary_channel_id;

        // ── Phase 3: interactive-tx negotiation ─────────────────────────────

        // Even serial IDs (0, 2, 4 …) for the initiator.
        let mut next_serial_id: u64 = 0;
        // Track whether we emitted at least one real UTXO input (for witness).
        let mut used_real_utxo = false;

        let num_rounds = rng.random_range(0..=MAX_ROUNDS);
        for _ in 0..num_rounds {
            let action = rng.random_range(0u8..3);
            match action {
                // Propose a new input.
                0 => {
                    let serial_id =
                        builder.append(Operation::LoadAmount(next_serial_id), &[]);
                    next_serial_id = next_serial_id.wrapping_add(2);

                    // 50% chance: use a real UTXO from context (UTXO index 0).
                    // The executor will handle LoadFundingUtxoRawTx(0) returning
                    // an error if no UTXOs are in context — that's fine for AFL++
                    // mutations, which may run with or without funded context.
                    let (prevtx, prevtx_vout) = if !used_real_utxo && rng.random_range(0u8..2) == 0 {
                        used_real_utxo = true;
                        let raw_tx = builder.append(Operation::LoadFundingUtxoRawTx(0), &[]);
                        let vout   = builder.append(Operation::LoadFundingUtxoVout(0), &[]);
                        (raw_tx, vout)
                    } else {
                        let raw_tx = builder.pick_variable(VariableType::Bytes, rng);
                        let vout   = builder.pick_variable(VariableType::BlockHeight, rng);
                        (raw_tx, vout)
                    };
                    let sequence = builder.pick_variable(VariableType::BlockHeight, rng);

                    let msg = builder.append(
                        Operation::BuildTxAddInput,
                        &[channel_id, serial_id, prevtx, prevtx_vout, sequence],
                    );
                    builder.append(Operation::SendMessage, &[msg]);
                    builder.append(Operation::RecvTxAddInput, &[]);
                }
                // Propose a new output.
                1 => {
                    let serial_id =
                        builder.append(Operation::LoadAmount(next_serial_id), &[]);
                    next_serial_id = next_serial_id.wrapping_add(2);

                    let sats = builder.pick_variable(VariableType::Amount, rng);
                    let script = builder.pick_variable(VariableType::Bytes, rng);

                    let msg = builder.append(
                        Operation::BuildTxAddOutput,
                        &[channel_id, serial_id, sats, script],
                    );
                    builder.append(Operation::SendMessage, &[msg]);
                    builder.append(Operation::RecvTxAddOutput, &[]);
                }
                // Remove a previously added input or output.
                _ => {
                    if next_serial_id >= 2 {
                        let target_serial = rng.random_range(0..next_serial_id / 2) * 2;
                        let serial_id =
                            builder.append(Operation::LoadAmount(target_serial), &[]);
                        let op = if rng.random_range(0..2) == 0 {
                            Operation::BuildTxRemoveInput
                        } else {
                            Operation::BuildTxRemoveOutput
                        };
                        let msg = builder.append(op, &[channel_id, serial_id]);
                        builder.append(Operation::SendMessage, &[msg]);
                        // BOLT 2: peer does NOT automatically reply to a remove
                        // message — no RecvTx* call here.
                    } else {
                        // No prior inputs/outputs — emit a fresh output instead.
                        let serial_id =
                            builder.append(Operation::LoadAmount(next_serial_id), &[]);
                        next_serial_id = next_serial_id.wrapping_add(2);

                        let sats = builder.pick_variable(VariableType::Amount, rng);
                        let script = builder.pick_variable(VariableType::Bytes, rng);

                        let msg = builder.append(
                            Operation::BuildTxAddOutput,
                            &[channel_id, serial_id, sats, script],
                        );
                        builder.append(Operation::SendMessage, &[msg]);
                        builder.append(Operation::RecvTxAddOutput, &[]);
                    }
                }
            }
        }

        // ── Phase 4: tx_abort OR tx_complete ────────────────────────────────

        let abort_roll: u8 = rng.random_range(0..5); // 0 = abort (20%), 1..4 = normal
        if abort_roll == 0 {
            // Abort path: send tx_abort and stop.
            let abort_data = builder.pick_variable(VariableType::Bytes, rng);
            let tx_abort_msg =
                builder.append(Operation::BuildTxAbort, &[channel_id, abort_data]);
            builder.append(Operation::SendMessage, &[tx_abort_msg]);
            return;
        }

        // Normal path: signal we are done adding inputs/outputs.
        let tx_complete_msg = builder.append(Operation::BuildTxComplete, &[channel_id]);
        builder.append(Operation::SendMessage, &[tx_complete_msg]);

        // RecvTxComplete drains CLN's interactive-tx contributions AND records
        // them in executor state for ComputeFundingWitness.
        builder.append(Operation::RecvTxComplete, &[]);

        // ── Phase 5: tx_signatures ──────────────────────────────────────────

        // Always try to receive CLN's tx_signatures first (if CLN has the
        // lower funding_pubkey, CLN sends first per BOLT 2).
        let txid_bytes = builder.append(Operation::RecvTxSignatures, &[]);

        // Witnesses: use BIP 143 real signing if we used a real UTXO input,
        // or pick random bytes (AFL++ explores both paths).
        let witnesses = if used_real_utxo {
            // 50% of real-UTXO programs use ComputeFundingWitness (real sig),
            // 50% use random bytes (AFL++ will mutate toward valid from both).
            if rng.random_range(0u8..2) == 0 {
                builder.append(Operation::ComputeFundingWitness, &[])
            } else {
                builder.pick_variable(VariableType::Bytes, rng)
            }
        } else {
            // No real UTXO input — random witnesses for AFL++ mutation.
            builder.pick_variable(VariableType::Bytes, rng)
        };

        let tx_sigs_msg = builder.append(
            Operation::BuildTxSignatures,
            &[channel_id, txid_bytes, witnesses],
        );
        builder.append(Operation::SendMessage, &[tx_sigs_msg]);

        // ── Phase 6: RBF round (optional, 20%) ──────────────────────────────
        //
        // Drives `handle_peer_tx_init_rbf` in CLN's `dualopend.c`.  We send
        // `tx_init_rbf` with a bumped feerate, await CLN's `tx_ack_rbf`, then
        // do a second (lightweight) interactive-tx round before sending new
        // `tx_signatures`.

        let rbf_roll: u8 = rng.random_range(0..5); // 0 = RBF (20%)
        if rbf_roll == 0 {
            let new_locktime         = builder.pick_variable(VariableType::BlockHeight, rng);
            let new_feerate          = builder.pick_variable(VariableType::FeeratePerKw, rng);
            let new_contribution     = builder.pick_variable(VariableType::SignedAmount, rng);
            let req_confirmed: u8    = rng.random_range(0u8..2);
            let req_confirmed_var    = builder.append(Operation::LoadU8(req_confirmed), &[]);
            let rbf_msg = builder.append(
                Operation::BuildTxInitRbf,
                &[channel_id, new_locktime, new_feerate, new_contribution, req_confirmed_var],
            );
            builder.append(Operation::SendMessage, &[rbf_msg]);
            builder.append(Operation::RecvTxAckRbf, &[]);

            // Second interactive-tx round (0–2 rounds for the RBF tx).
            let rbf_rounds = rng.random_range(0usize..=2);
            let mut rbf_serial: u64 = 0;
            for _ in 0..rbf_rounds {
                if rng.random_range(0u8..2) == 0 {
                    let serial_id =
                        builder.append(Operation::LoadAmount(rbf_serial), &[]);
                    rbf_serial = rbf_serial.wrapping_add(2);
                    let sats   = builder.pick_variable(VariableType::Amount, rng);
                    let script = builder.pick_variable(VariableType::Bytes, rng);
                    let msg = builder.append(
                        Operation::BuildTxAddOutput,
                        &[channel_id, serial_id, sats, script],
                    );
                    builder.append(Operation::SendMessage, &[msg]);
                    builder.append(Operation::RecvTxAddOutput, &[]);
                }
            }

            let rbf_complete = builder.append(Operation::BuildTxComplete, &[channel_id]);
            builder.append(Operation::SendMessage, &[rbf_complete]);
            builder.append(Operation::RecvTxComplete, &[]);

            let rbf_txid = builder.append(Operation::RecvTxSignatures, &[]);
            let rbf_witnesses = builder.pick_variable(VariableType::Bytes, rng);
            let rbf_sigs = builder.append(
                Operation::BuildTxSignatures,
                &[channel_id, rbf_txid, rbf_witnesses],
            );
            builder.append(Operation::SendMessage, &[rbf_sigs]);
        }

        // ── Phase 7: channel_reestablish (optional, 10%) ─────────────────────
        //
        // Drives `handle_peer_reestablish` in `dualopend.c` and `closingd.c`.
        // Values are semantically correct for a channel that has exchanged the
        // initial commitment tx (next_commitment_number=1) but no revocations
        // (next_revocation_number=0, per_commitment_secret=zeros).

        let reestablish_roll: u8 = rng.random_range(0..10); // 0 = reestablish (10%)
        if reestablish_roll == 0 {
            let next_commit_num  = builder.append(Operation::LoadAmount(1), &[]);
            let next_revoke_num  = builder.append(Operation::LoadAmount(0), &[]);
            let secret           = builder.append(Operation::LoadBytes(vec![0u8; 32]), &[]);
            // my_current_per_commitment_point: pick a random Point from the
            // variable pool (likely one of the generated basepoints).
            let per_commit_point = builder.pick_variable(VariableType::Point, rng);
            let reestablish_msg  = builder.append(
                Operation::BuildChannelReestablish,
                &[channel_id, next_commit_num, next_revoke_num, secret, per_commit_point],
            );
            builder.append(Operation::SendMessage, &[reestablish_msg]);
            builder.append(Operation::RecvChannelReestablish, &[]);
        }

        // ── Phase 8: shutdown + closing_signed (optional, 20%) ───────────────
        //
        // Drives `handle_peer_shutdown` (dualopend.c) and then the
        // fee-convergence loop in `closingd.c::handle_peer_closing_signed`.
        // RecvShutdown consumes CLN's shutdown reply before we send
        // closing_signed, keeping the message stream in sync.

        let shutdown_roll: u8 = rng.random_range(0..5); // 0 = shutdown+close (20%)
        if shutdown_roll == 0 {
            let scriptpubkey = builder.pick_variable(VariableType::Bytes, rng);
            let shutdown_msg =
                builder.append(Operation::BuildShutdown, &[channel_id, scriptpubkey]);
            builder.append(Operation::SendMessage, &[shutdown_msg]);
            // Wait for CLN's shutdown reply before sending closing_signed.
            builder.append(Operation::RecvShutdown, &[]);

            // 1–3 rounds of closing_signed fee negotiation.
            let close_rounds: u8 = rng.random_range(1..=3);
            for _ in 0..close_rounds {
                let fee = builder.pick_variable(VariableType::Amount, rng);
                let sig = builder.pick_variable(VariableType::Bytes, rng);
                let cs_msg = builder.append(
                    Operation::BuildClosingSigned,
                    &[channel_id, fee, sig],
                );
                builder.append(Operation::SendMessage, &[cs_msg]);
                builder.append(Operation::RecvClosingSigned, &[]);
            }
        }
    }
}
