//! Eclair dual-funding fuzzing scenario binary.
//!
//! Usage:
//!   cargo afl fuzz -i corpus/dual-funding -o findings/eclair \
//!     target/release/eclair_dual_funding

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::DualFundingScenario;
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<DualFundingScenario<EclairTarget>>()
}
