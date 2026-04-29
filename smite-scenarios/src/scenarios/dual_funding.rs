//! Dual-funding (BOLT 2 interactive-tx) fuzzing scenario.
//!
//! # Protocol overview
//!
//! The BOLT 2 dual-funding flow (BIP 174 / BOLT 2 §6.1) is:
//!
//! ```text
//! fuzzer (initiator)              target (responder)
//!   |--- open_channel2 (64) -------->|
//!   |<-- accept_channel2 (65) --------|
//!   |--- tx_add_input (66) ---------->|
//!   |<-- tx_add_input / tx_add_output-|  (0..N rounds)
//!   |--- tx_complete (70) ----------->|
//!   |<-- tx_complete (70) ------------|
//!   |--- tx_signatures (71) --------->|
//! ```
//!
//! # Snapshot placement
//!
//! The pre-snapshot setup:
//!   1. Starts the Lightning target with dual-funding enabled.
//!   2. Completes the Noise handshake.
//!   3. Exchanges BOLT 1 `init` messages.
//!   4. Records target pubkey, chain hash, block height → `ProgramContext`.
//!   5. Takes the Nyx snapshot.
//!
//! Each fuzz iteration:
//!   1. Decodes the fuzz input as a serialized `Program`.
//!   2. Executes the program via `Executor` against the live connection.
//!   3. Checks whether the target is still alive.
//!
//! # Chain hash
//!
//! The `chain_hash` in `ProgramContext` is the genesis block hash in Bitcoin
//! internal-byte-order (little-endian).  Nodes must agree on the chain hash or
//! they will disconnect.  Use [`REGTEST_CHAIN_HASH`] for local bitcoind regtest,
//! or [`SIGNET_CHAIN_HASH`] for signet.
//!
//! > **For production-quality fuzzing**: run the target on **signet** so
//! > the fuzzer exercises real-network chain parameters (e.g., different
//! > genesis hash, P2TR address scripts, actual fee levels).  Set
//! > `DUAL_FUNDING_CHAIN=signet` in the environment to switch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::SmallRng;
use secp256k1::PublicKey;
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite_ir::{Executor, InteractiveTxGenerator, ProgramBuilder, ProgramContext};
use smite_ir::generators::Generator;

use super::{connect_to_target, ping_pong};
use crate::targets::Target;

/// Timeout for connection and per-message I/O.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Counts inputs that successfully deserialized as `smite_ir::Program`
/// (real IR mutation reaches the executor).
static DECODE_OK: AtomicU64 = AtomicU64::new(0);

/// Counts inputs that failed to deserialize and fell back to the seeded
/// `InteractiveTxGenerator` (AFL's mutation effectively discarded).
static DECODE_ERR: AtomicU64 = AtomicU64::new(0);

/// Regtest genesis block hash (Bitcoin internal byte order, little-endian).
///
/// This is the chain hash that all Bitcoin regtest nodes advertise.
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b,
    0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88,
    0x91, 0x0f,
];

/// Signet genesis block hash (Bitcoin internal byte order, little-endian).
///
/// Use this when fuzzing against signet-configured nodes for more realistic
/// fee rates, script types, and chain-level interactions.
pub const SIGNET_CHAIN_HASH: [u8; 32] = [
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb,
    0xc9, 0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00,
    0x00, 0x00,
];

/// Selects the chain hash based on the `DUAL_FUNDING_CHAIN` environment variable.
///
/// - `signet` → `SIGNET_CHAIN_HASH`
/// - anything else (or unset) → `REGTEST_CHAIN_HASH`
fn chain_hash_from_env() -> [u8; 32] {
    match std::env::var("DUAL_FUNDING_CHAIN").as_deref() {
        Ok("signet") => SIGNET_CHAIN_HASH,
        _ => REGTEST_CHAIN_HASH,
    }
}

/// Fuzzes the BOLT 2 dual-funding interactive-transaction protocol.
///
/// The fuzz input is interpreted as a serialized [`smite_ir::Program`].  If
/// the bytes cannot be decoded as a program, the generator is used to produce
/// a random well-formed program using the bytes as an RNG seed.  This keeps
/// the corpus productive even for early random inputs.
pub struct DualFundingScenario<T: Target> {
    target: T,
    conn: NoiseConnection,
    ctx: ProgramContext,
}

impl<T: Target> Scenario for DualFundingScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;

        // Warm-up connection: ensure the target's JIT and connection handling
        // code paths are hot before the snapshot is taken.  This matters most
        // for JVM targets (Eclair) but doesn't hurt native targets (CLN, LDK).
        let mut warmup = connect_to_target(&target, TIMEOUT)?;
        ping_pong(&mut warmup)?;
        drop(warmup);

        // Snapshot connection: the Noise handshake + init exchange happen here.
        // Everything *after* this point is replayed on every fuzz iteration.
        let conn = connect_to_target(&target, TIMEOUT)?;

        // Extract the target's public key from the already-completed handshake.
        let target_pubkey_obj: PublicKey = *target.pubkey();
        let mut target_pubkey = [0u8; 33];
        target_pubkey.copy_from_slice(&target_pubkey_obj.serialize());

        let chain_hash = chain_hash_from_env();

        // Query the target for fuzzer-controlled UTXOs.  These are funded
        // regtest P2WPKH UTXOs where the fuzzer holds the private key, used
        // for real dual-funding contributions (tx_add_input + BIP 143 signing).
        let funding_utxos = target.funding_utxos();
        if funding_utxos.is_empty() {
            log::warn!("No fuzzer UTXOs available — real dual-funding disabled (zero-contribution mode)");
        } else {
            log::info!(
                "Loaded {} fuzzer UTXO(s) for real dual-funding contributions",
                funding_utxos.len()
            );
        }

        let ctx = ProgramContext {
            target_pubkey,
            chain_hash,
            block_height: 0, // updated dynamically if needed
            target_features: Vec::new(),
            funding_utxos,
        };

        log::info!(
            "DualFundingScenario ready. chain={}",
            if chain_hash == SIGNET_CHAIN_HASH { "signet" } else { "regtest" }
        );

        Ok(Self { target, conn, ctx })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        // Try to decode the input as a serialized IR program.  Fall back to
        // generating a random program using the first 8 bytes as an RNG seed.
        let program = match postcard::from_bytes::<smite_ir::Program>(input) {
            Ok(p) => {
                DECODE_OK.fetch_add(1, Ordering::Relaxed);
                p
            }
            Err(_) => {
                DECODE_ERR.fetch_add(1, Ordering::Relaxed);
                // Derive a seed from the first 8 input bytes (0-padded if short).
                let mut seed_bytes = [0u8; 8];
                let copy_len = input.len().min(8);
                seed_bytes[..copy_len].copy_from_slice(&input[..copy_len]);
                let seed = u64::from_le_bytes(seed_bytes);

                let mut rng = SmallRng::seed_from_u64(seed);
                let mut builder = ProgramBuilder::new();
                InteractiveTxGenerator.generate(&mut builder, &mut rng);
                builder.build()
            }
        };

        let total = DECODE_OK.load(Ordering::Relaxed) + DECODE_ERR.load(Ordering::Relaxed);
        if total.is_multiple_of(100) && total > 0 {
            let ok = DECODE_OK.load(Ordering::Relaxed);
            let err = DECODE_ERR.load(Ordering::Relaxed);
            let pct = (ok as f64) * 100.0 / (total as f64);
            eprintln!(
                "decode_rate: total={total} ok={ok} err={err} ok_pct={pct:.2}%"
            );
            let _ = std::fs::write(
                "/tmp/decode_rate.txt",
                format!("total={total} ok={ok} err={err} ok_pct={pct:.4}%\n"),
            );
        }

        // Execute the IR program against the live connection.
        let mut executor = Executor::new(&mut self.conn, &self.ctx);
        match executor.run(&program) {
            Ok(()) => {
                log::debug!("program executed successfully");
            }
            Err(e) => {
                // Execution errors (protocol violations, unexpected messages)
                // are not themselves crashes — they mean the target correctly
                // rejected our message.  Log and continue.
                log::debug!("executor error: {e:?}");
            }
        }

        // Synchronize: send ping, wait for pong.  This ensures the target has
        // fully processed all messages before we check for crashes.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("ping_pong failed: {e:?}");
            if e.is_timeout() {
                return ScenarioResult::Fail("target hung (ping timeout)".into());
            }
            // Connection closed — target may have disconnected after a protocol
            // error, or it may have crashed.  Fall through to check_alive.
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("check_alive: {e:?}");
            return ScenarioResult::Fail("target crashed".into());
        }

        ScenarioResult::Ok
    }
}

