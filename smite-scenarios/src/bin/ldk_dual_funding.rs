//! LDK (Lightning Dev Kit) dual-funding fuzzing scenario binary.
//!
//! Usage:
//!   cargo afl fuzz -i corpus/dual-funding -o findings/ldk \
//!     target/release/ldk_dual_funding

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::DualFundingScenario;
use smite_scenarios::targets::LdkTarget;

fn main() -> std::process::ExitCode {
    smite_run::<DualFundingScenario<LdkTarget>>()
}
