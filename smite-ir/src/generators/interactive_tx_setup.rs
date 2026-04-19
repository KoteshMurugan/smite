//! Reusable BOLT 2 dual-funding channel-open setup primitive.
//!
//! `InteractiveTxSetup` emits the *handshake* phases of a dual-funding flow
//! -- `open_channel2` (type 64) followed by `accept_channel2` (type 65) --
//! and returns the variable handles a downstream flow generator needs to
//! continue: the `temporary_channel_id` (used as `state->channel_id` by CLN
//! throughout the interactive-tx phase), the funding pubkey (for later
//! BIP 143 signing), the negotiated `funding_satoshis` and `locktime`, and
//! the parsed `accept_channel2` compound (so callers can `Extract2*` any
//! field they need).
//!
//! # Why this is its own primitive
//!
//! The upstream IR design (see <https://github.com/morehouse/smite/issues/5>)
//! distinguishes *message generators* (one BOLT message), *action generators*
//! (one side effect), and *flow generators* (compose the smaller ones).
//! `InteractiveTxSetup` is a setup-flow primitive: it's the prefix that every
//! dual-funding-derived flow needs (interactive-tx, splice when it lands,
//! channel_ready, RBF restart).  Inlining it into a single monolithic
//! generator forces every new flow to copy ~80 lines of phase 1 / phase 2
//! setup; lifting it out lets the next flow add a single `let setup =
//! InteractiveTxSetup.emit(...)` line.
//!
//! # What this primitive intentionally does *not* do
//!
//! - It does not advance into tx_add_input / tx_add_output / tx_complete.
//!   That belongs to whichever flow composes this setup.
//! - It does not emit `Recv` operations beyond `RecvAcceptChannel2`.  The
//!   first interactive-tx round is the next caller's responsibility.
//! - It does not commit to a `channel_id` derivation.  CLN uses
//!   `temporary_channel_id` for every interactive-tx message until
//!   `tx_signatures`, so the setup output exposes that field directly.
//!   When a future flow needs the *derived* channel_id it can append
//!   `Operation::ComputeChannelIdV2` from the two revocation basepoints.

use rand::Rng;

use super::super::builder::ProgramBuilder;
use super::super::operation::Operation;
use super::super::VariableType;

/// Variable handles produced by [`InteractiveTxSetup::emit`].
///
/// Each field is a *variable index* into the program being built -- the
/// same indices `ProgramBuilder::pick_variable` returns -- so callers can
/// thread them straight into subsequent `builder.append(...)` calls.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveTxSetupOutputs {
    /// `temporary_channel_id` from the `open_channel2` message.
    ///
    /// Per BOLT 2 dual-funding, CLN's `state->channel_id` is set to this
    /// value throughout the interactive-tx phase (until `tx_signatures`).
    /// All `tx_add_*`, `tx_complete`, and `tx_abort` messages must use this
    /// channel_id or `check_channel_id` rejects them in `dualopend.c`.
    pub temporary_channel_id: usize,

    /// Our `revocation_basepoint` -- input to `ComputeChannelIdV2` if the
    /// caller later needs the derived channel_id (e.g., post-tx_signatures).
    pub revocation_basepoint: usize,

    /// Our `funding_pubkey`.  Required by BIP 143 funding-witness signing
    /// (`ComputeFundingWitness`) and by `BuildCommitmentSigned` flows.
    pub funding_pubkey: usize,

    /// The `funding_satoshis` we offered in `open_channel2`.  Surfaced so
    /// downstream flows (RBF, splice) can preserve or bump it.
    pub funding_satoshis: usize,

    /// The `locktime` we offered in `open_channel2`.  Surfaced for the
    /// same reason as `funding_satoshis`.
    pub locktime: usize,

    /// The compound `AcceptChannel2` variable returned by the target.
    /// Use `Operation::ExtractAcceptChannel2(field)` to pull individual
    /// fields out of it.
    pub accept_channel2: usize,
}

/// Emits the BOLT 2 dual-funding handshake (`open_channel2` /
/// `accept_channel2`) into a `ProgramBuilder` and returns the variable
/// handles a downstream flow needs to continue the negotiation.
///
/// The setup uses `Operation::ComputeTempChannelIdV2` to derive the
/// temporary_channel_id from our `revocation_basepoint`, matching CLN's
/// `derive_tmp_channel_id` formula in `common/channel_id.c`.  Picking a
/// random ChannelId here would cause CLN to reject `open_channel2` before
/// the interactive-tx phase ever starts, so the fuzzer would never explore
/// any of the deeper code paths the harness is built to reach.
pub struct InteractiveTxSetup;

impl InteractiveTxSetup {
    /// Emit the handshake instructions into `builder` and return the
    /// resulting variable handles.
    pub fn emit(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut impl Rng,
    ) -> InteractiveTxSetupOutputs {
        // Public keys are generated fresh so each is a cryptographically
        // distinct secp256k1 point.  They are consumed once each by
        // BuildOpenChannel2; reuse would still type-check but would let the
        // generator emit nonsensical channels (e.g., funding_pubkey ==
        // revocation_basepoint).
        let funding_pubkey = builder.generate_fresh(VariableType::Point, rng);
        let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
        let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // Protocol parameters -- pick from the existing variable pool when
        // possible (75/15/10 reuse strategy in ProgramBuilder).  This is
        // what gives mutators something to swap between independently
        // generated programs.
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let temporary_channel_id =
            builder.append(Operation::ComputeTempChannelIdV2, &[revocation_basepoint]);
        let funding_feerate_perkw = builder.pick_variable(VariableType::FeeratePerKw, rng);
        let commitment_feerate_perkw = builder.pick_variable(VariableType::FeeratePerKw, rng);
        let funding_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let dust_limit_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let max_htlc_value_in_flight_msat = builder.pick_variable(VariableType::Amount, rng);
        let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
        let to_self_delay = builder.pick_variable(VariableType::U16, rng);
        let max_accepted_htlcs = builder.pick_variable(VariableType::U16, rng);
        let locktime = builder.pick_variable(VariableType::BlockHeight, rng);
        let channel_flags = builder.pick_variable(VariableType::U8, rng);
        let upfront_shutdown_script = builder.pick_variable(VariableType::Bytes, rng);
        let channel_type = builder.pick_variable(VariableType::Features, rng);

        let open_ch2_msg = builder.append(
            Operation::BuildOpenChannel2,
            &[
                chain_hash,
                temporary_channel_id,
                funding_feerate_perkw,
                commitment_feerate_perkw,
                funding_satoshis,
                dust_limit_satoshis,
                max_htlc_value_in_flight_msat,
                htlc_minimum_msat,
                to_self_delay,
                max_accepted_htlcs,
                locktime,
                funding_pubkey,
                revocation_basepoint,
                payment_basepoint,
                delayed_payment_basepoint,
                htlc_basepoint,
                first_per_commitment_point,
                second_per_commitment_point,
                channel_flags,
                upfront_shutdown_script,
                channel_type,
            ],
        );
        builder.append(Operation::SendMessage, &[open_ch2_msg]);

        let accept_channel2 = builder.append(Operation::RecvAcceptChannel2, &[]);

        InteractiveTxSetupOutputs {
            temporary_channel_id,
            revocation_basepoint,
            funding_pubkey,
            funding_satoshis,
            locktime,
            accept_channel2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Program, VariableType};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    /// Run the setup against a fresh builder and return both the program
    /// and the recorded outputs.
    fn build_setup(seed: u64) -> (Program, InteractiveTxSetupOutputs) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let mut builder = ProgramBuilder::new();
        let outputs = InteractiveTxSetup.emit(&mut builder, &mut rng);
        (builder.build(), outputs)
    }

    /// Setup must produce a type-correct program for any seed.  Type errors
    /// would have panicked inside `ProgramBuilder::append`, so reaching the
    /// end of the loop is the assertion.
    #[test]
    fn setup_is_type_correct() {
        for seed in 0..100 {
            let _ = build_setup(seed);
        }
    }

    /// Setup output handles must point at instructions that produce the
    /// expected `VariableType`.  Catches any future drift between the
    /// outputs struct documentation and the actual emitted ops.
    #[test]
    fn setup_outputs_have_expected_types() {
        let (program, outputs) = build_setup(0);

        let type_at = |idx: usize| -> Option<VariableType> {
            program.instructions[idx].operation.output_type()
        };

        assert_eq!(type_at(outputs.temporary_channel_id), Some(VariableType::ChannelId));
        assert_eq!(type_at(outputs.revocation_basepoint), Some(VariableType::Point));
        assert_eq!(type_at(outputs.funding_pubkey), Some(VariableType::Point));
        assert_eq!(type_at(outputs.funding_satoshis), Some(VariableType::Amount));
        assert_eq!(type_at(outputs.locktime), Some(VariableType::BlockHeight));
        assert_eq!(
            type_at(outputs.accept_channel2),
            Some(VariableType::AcceptChannel2),
        );
    }

    /// Setup output handles must be in-bounds indices into the program.
    /// Any future change that returns indices computed before they are
    /// emitted will trip this test.
    #[test]
    fn setup_outputs_are_in_bounds() {
        for seed in 0..20 {
            let (program, outputs) = build_setup(seed);
            let n = program.instructions.len();
            for (name, idx) in [
                ("temporary_channel_id", outputs.temporary_channel_id),
                ("revocation_basepoint", outputs.revocation_basepoint),
                ("funding_pubkey", outputs.funding_pubkey),
                ("funding_satoshis", outputs.funding_satoshis),
                ("locktime", outputs.locktime),
                ("accept_channel2", outputs.accept_channel2),
            ] {
                assert!(idx < n, "seed {seed}: {name} index {idx} out of bounds (n={n})");
            }
        }
    }

    /// The emitted program must contain exactly the handshake ops, in
    /// order: BuildOpenChannel2 -> SendMessage -> RecvAcceptChannel2.
    #[test]
    fn setup_emits_handshake_ops_in_order() {
        let (program, _) = build_setup(0);
        let ops: Vec<&Operation> = program.instructions.iter().map(|i| &i.operation).collect();

        let build_idx = ops
            .iter()
            .position(|op| matches!(op, Operation::BuildOpenChannel2))
            .expect("BuildOpenChannel2 missing");
        let send_idx = ops
            .iter()
            .position(|op| matches!(op, Operation::SendMessage))
            .expect("SendMessage missing");
        let recv_idx = ops
            .iter()
            .position(|op| matches!(op, Operation::RecvAcceptChannel2))
            .expect("RecvAcceptChannel2 missing");

        assert!(
            build_idx < send_idx && send_idx < recv_idx,
            "expected Build < Send < Recv, got {build_idx} {send_idx} {recv_idx}",
        );
    }

    /// The setup produces a serializable program (postcard roundtrip is
    /// what AFL++ uses to ship the program into the Nyx VM).
    #[test]
    fn setup_program_postcard_roundtrip() {
        let (program, _) = build_setup(13);
        let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
        let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
        assert_eq!(program, decoded);
    }
}
