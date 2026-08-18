#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "common/exec_diff.rs"]
mod exec_diff;

use exec_diff::{ALL_LANGS, BATTERY, Spec, grade};
use wasmtime::Config;

const SIMD_DIFF: &str = include_str!("fixtures/simd_diff.wat");
const SIMD_LANES_DIFF: &str = include_str!("fixtures/simd_lanes_diff.wat");

fn simd_config(config: &mut Config) {
    config.wasm_simd(true).wasm_relaxed_simd(true);
}

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
