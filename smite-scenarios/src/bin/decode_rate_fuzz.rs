//! Stripped-down AFL target that ONLY measures the postcard decode rate.
//!
//! Mirrors the match in `dual_funding.rs::run()` lines 163-184 exactly: try to
//! decode the input as a `smite_ir::Program`; on failure, build a program from
//! the seeded `InteractiveTxGenerator`. No CLN, no bitcoind, no network — pure
//! decode + fallback.
//!
//! Why a separate binary: the full `cln_dual_funding` harness gets ~2-5
//! execs/sec because every iteration involves a real Lightning interaction.
//! The decode rate is a per-input *property of AFL's mutation output* — it
//! does not depend on CLN being alive. By stripping CLN out, this binary
//! runs at thousands of execs/sec, so a few minutes of fuzzing yields
//! statistically tight (±0.1%) numbers.
//!
//! Usage:
//!   cargo afl build --release --bin decode_rate_fuzz
//!   AFL_SKIP_CPUFREQ=1 cargo afl fuzz \
//!     -i <existing_queue> -o /tmp/decode_findings \
//!     target/release/decode_rate_fuzz
//!
//! Periodically writes /tmp/decode_rate.txt with the running totals.

use std::sync::atomic::{AtomicU64, Ordering};

use rand::SeedableRng;
use rand::rngs::SmallRng;
use smite_ir::generators::Generator;
use smite_ir::{InteractiveTxGenerator, ProgramBuilder};

static DECODE_OK: AtomicU64 = AtomicU64::new(0);
static DECODE_ERR: AtomicU64 = AtomicU64::new(0);

fn process(input: &[u8]) {
    match postcard::from_bytes::<smite_ir::Program>(input) {
        Ok(_p) => {
            DECODE_OK.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            DECODE_ERR.fetch_add(1, Ordering::Relaxed);
            // Mirror the fallback exactly so workloads stay representative.
            let mut seed_bytes = [0u8; 8];
            let copy_len = input.len().min(8);
            seed_bytes[..copy_len].copy_from_slice(&input[..copy_len]);
            let seed = u64::from_le_bytes(seed_bytes);

            let mut rng = SmallRng::seed_from_u64(seed);
            let mut builder = ProgramBuilder::new();
            InteractiveTxGenerator.generate(&mut builder, &mut rng);
            let _ = builder.build();
        }
    }

    let total = DECODE_OK.load(Ordering::Relaxed) + DECODE_ERR.load(Ordering::Relaxed);
    if total.is_multiple_of(1000) && total > 0 {
        let ok = DECODE_OK.load(Ordering::Relaxed);
        let err = DECODE_ERR.load(Ordering::Relaxed);
        let pct = (ok as f64) * 100.0 / (total as f64);
        let _ = std::fs::write(
            "/tmp/decode_rate.txt",
            format!("total={total} ok={ok} err={err} ok_pct={pct:.4}%\n"),
        );
    }
}

fn main() {
    afl::fuzz!(|data: &[u8]| {
        process(data);
    });
}
