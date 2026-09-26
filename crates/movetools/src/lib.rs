//! Developer tooling for Move packages on Thrylos: `thrylos move new`, `build`
//! and `test`.
//!
//! Tier C: nothing here is consensus. It compiles against the chain's own system
//! packages (their sources are built in), checks a build with the chain's own
//! publishing checks, and runs tests in the chain's own Move runtime with the
//! same natives and limits, so a package behaves in `test` as it will on the
//! network (apart from gas, which `test` bounds generously rather than
//! reporting).

pub mod compile;
pub mod scaffold;
pub mod sources;
pub mod testing;

pub use compile::{
    build, build_is_stale, built_files, check, check_bytes, source_files, write_build, Built,
    Dependency, Options, BUILD_DIR,
};
pub use move_core_types::account_address::AccountAddress;
pub use scaffold::new_package;
pub use testing::{run_tests, Outcome, TestReport, TestResult, DEFAULT_TEST_GAS};
