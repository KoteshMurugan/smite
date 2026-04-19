//! CLN (Core Lightning) dual-funding fuzzing scenario binary.
//!
//! Requires CLN to be started with `--experimental-dual-fund`.
//!
//! Usage:
//!   cargo afl fuzz -i corpus/dual-funding -o findings/cln \
//!     target/release/cln_dual_funding

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::DualFundingScenario;
use smite_scenarios::targets::ClnTarget;

fn main() -> std::process::ExitCode {
    smite_run::<DualFundingScenario<ClnTarget>>()
}
