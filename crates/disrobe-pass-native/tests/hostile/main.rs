#[path = "../support/compiler_toolchain.rs"]
#[allow(clippy::panic, clippy::redundant_pub_crate)]
mod compiler_toolchain;
#[path = "../support/hostile_inputs.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod hostile_inputs;
#[path = "../support/native_entry_points.rs"]
#[allow(clippy::redundant_pub_crate)]
mod native_entry_points;

mod fuzz_resilience;
mod header_parse_hardening;
