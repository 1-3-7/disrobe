#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "common/exec_diff.rs"]
mod exec_diff;

use exec_diff::{
    ALL_LANGS, BATTERY, NON_TRAPPING_BATTERY, ReferenceSpec, Spec, grade, grade_against_reference,
};
use wasmtime::Config;

const ATOMICS_DIFF: &str = include_str!("fixtures/atomics_diff.wat");
const WIDE_DIFF: &str = include_str!("fixtures/wide_diff.wat");
const REFTABLE_DIFF: &str = include_str!("fixtures/reftable_diff.wat");
const SHARED_DIFF: &str = include_str!("fixtures/shared_everything_diff.wat");
const SHARED_REF: &str = include_str!("fixtures/shared_everything_ref.wat");
const DIVREM_TRUNC_DIFF: &str = include_str!("fixtures/divrem_trunc_diff.wat");

fn atomics_config(config: &mut Config) {
    config.wasm_threads(true).wasm_bulk_memory(true);
}

fn wide_config(config: &mut Config) {
    config.wasm_wide_arithmetic(true).wasm_multi_value(true);
}

fn reftable_config(config: &mut Config) {
    config
        .wasm_bulk_memory(true)
        .wasm_reference_types(true)
        .wasm_function_references(true)
        .wasm_gc(true);
}

fn baseline_config(config: &mut Config) {
    config.wasm_multi_value(true);
}

#[test]
fn lifted_targets_execute_atomics_equivalently_to_wasmtime() {
    grade(&Spec {
        label: "atomics",
        wat: ATOMICS_DIFF,
        configure: atomics_config,
        langs: &ALL_LANGS,
        min_exports: 24,
        ungraded: &[],
        battery: &BATTERY,
    });
}

#[test]
fn lifted_targets_execute_wide_arithmetic_equivalently_to_wasmtime() {
    grade(&Spec {
        label: "wide",
        wat: WIDE_DIFF,
        configure: wide_config,
        langs: &ALL_LANGS,
        min_exports: 10,
        ungraded: &[],
        battery: &BATTERY,
    });
}

#[test]
fn lifted_targets_execute_reference_and_table_equivalently_to_wasmtime() {
    grade(&Spec {
        label: "reftable",
        wat: REFTABLE_DIFF,
        configure: reftable_config,
        langs: &ALL_LANGS,
        min_exports: 12,
        ungraded: &[],
        battery: &BATTERY,
    });
}

#[test]
fn lifted_targets_execute_shared_everything_like_its_non_atomic_equivalent() {
    grade_against_reference(&ReferenceSpec {
        label: "shared_everything",
        wat: SHARED_DIFF,
        reference_wat: SHARED_REF,
        configure: reftable_config,
        langs: &ALL_LANGS,
        min_exports: 16,
    });
}

#[test]
fn lifted_targets_execute_divide_remainder_and_truncation_on_non_trapping_inputs() {
    grade(&Spec {
        label: "divrem_trunc",
        wat: DIVREM_TRUNC_DIFF,
        configure: baseline_config,
        langs: &ALL_LANGS,
        min_exports: 16,
        ungraded: &[],
        battery: &NON_TRAPPING_BATTERY,
    });
}
