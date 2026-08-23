#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[cfg(feature = "sandbox")]
#[path = "common/exec_diff.rs"]
mod exec_diff;

#[cfg(feature = "sandbox")]
use exec_diff::{ALL_LANGS, BATTERY, Spec, grade};
#[cfg(feature = "sandbox")]
use wasmtime::Config;

#[cfg(feature = "sandbox")]
const SIMD_DIFF: &str = include_str!("fixtures/simd_diff.wat");
#[cfg(feature = "sandbox")]
const SIMD_LANES_DIFF: &str = include_str!("fixtures/simd_lanes_diff.wat");

#[cfg(feature = "sandbox")]
fn simd_config(config: &mut Config) {
    config.wasm_simd(true).wasm_relaxed_simd(true);
}

#[cfg(feature = "sandbox")]
#[test]
fn lifted_targets_execute_simd_equivalently_to_wasmtime() {
    grade(&Spec {
        label: "simd",
        wat: SIMD_DIFF,
        configure: simd_config,
        langs: &ALL_LANGS,
        min_exports: 17,
        ungraded: &[],
        refused: &[],
        battery: &BATTERY,
    });
}

#[cfg(feature = "sandbox")]
#[test]
fn lifted_targets_execute_every_deterministic_lane_op_equivalently_to_wasmtime() {
    grade(&Spec {
        label: "simd_lanes",
        wat: SIMD_LANES_DIFF,
        configure: simd_config,
        langs: &ALL_LANGS,
        min_exports: 221,
        ungraded: &[],
        refused: &[],
        battery: &BATTERY,
    });
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_simd_differential_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasm_simd_differential`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
