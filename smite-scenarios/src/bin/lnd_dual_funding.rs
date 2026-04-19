//! LND dual-funding fuzzing scenario binary.
//!
//! Usage:
//!   cargo afl fuzz -i corpus/dual-funding -o findings/lnd \
//!     target/release/lnd_dual_funding

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::DualFundingScenario;
use smite_scenarios::targets::LndTarget;

fn main() -> std::process::ExitCode {
    smite_run::<DualFundingScenario<LndTarget>>()
}
