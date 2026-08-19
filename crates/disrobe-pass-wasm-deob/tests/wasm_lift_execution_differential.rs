#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

#[path = "common/exec_diff.rs"]
mod exec_diff;

use exec_diff::{
    ALL_LANGS, BATTERY, NON_TRAPPING_BATTERY, ReferenceSpec, Spec, grade, grade_against_reference,
    grade_traps,
};
use wasmtime::{Config, Trap};

const ATOMICS_DIFF: &str = include_str!("fixtures/atomics_diff.wat");
const ATOMICS_MISALIGNED_DIFF: &str = include_str!("fixtures/atomics_misaligned_diff.wat");
const ATOMICS_ALIGNED_OOB_DIFF: &str = include_str!("fixtures/atomics_aligned_oob_diff.wat");
const ATOMICS_ADDRESS_OVERFLOW_DIFF: &str =
    include_str!("fixtures/atomics_address_overflow_diff.wat");
const ATOMICS_MEMORY64_OVERFLOW_MISALIGNED_DIFF: &str =
    include_str!("fixtures/atomics_memory64_overflow_misaligned_diff.wat");
const ATOMICS_MEMORY64_ALIGNED_OFFSET_2POW53_DIFF: &str =
    include_str!("fixtures/atomics_memory64_aligned_offset_2pow53_diff.wat");
const ATOMICS_MEMORY64_UINT64_MAX_OFFSET_DIFF: &str =
    include_str!("fixtures/atomics_memory64_uint64_max_offset_diff.wat");
const ATOMICS_NARROW_CMPXCHG_DIFF: &str = include_str!("fixtures/atomics_narrow_cmpxchg_diff.wat");
const ATOMICS_WAIT_NOTIFY_DIFF: &str = include_str!("fixtures/atomics_wait_notify_diff.wat");
const ATOMICS_EVERY_OPCODE_DIFF: &str = include_str!("fixtures/atomics_every_opcode_diff.wat");
const WIDE_DIFF: &str = include_str!("fixtures/wide_diff.wat");
const REFTABLE_DIFF: &str = include_str!("fixtures/reftable_diff.wat");
const SHARED_DIFF: &str = include_str!("fixtures/shared_everything_diff.wat");
const SHARED_REF: &str = include_str!("fixtures/shared_everything_ref.wat");
const DIVREM_TRUNC_DIFF: &str = include_str!("fixtures/divrem_trunc_diff.wat");

fn atomics_config(config: &mut Config) {
    config
        .wasm_threads(true)
        .wasm_bulk_memory(true)
        .wasm_memory64(true);
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
        min_exports: 28,
        ungraded: &[],
        refused: &[],
        battery: &BATTERY,
    });
}

const EVERY_LINEAR_MEMORY_ATOMIC: [&str; 63] = [
    "i32.atomic.load",
    "i32.atomic.load8_u",
    "i32.atomic.load16_u",
    "i64.atomic.load",
    "i64.atomic.load8_u",
    "i64.atomic.load16_u",
    "i64.atomic.load32_u",
    "i32.atomic.store",
    "i32.atomic.store8",
    "i32.atomic.store16",
    "i64.atomic.store",
    "i64.atomic.store8",
    "i64.atomic.store16",
    "i64.atomic.store32",
    "i32.atomic.rmw.add",
    "i32.atomic.rmw8.add_u",
    "i32.atomic.rmw16.add_u",
    "i64.atomic.rmw.add",
    "i64.atomic.rmw8.add_u",
    "i64.atomic.rmw16.add_u",
    "i64.atomic.rmw32.add_u",
    "i32.atomic.rmw.sub",
    "i32.atomic.rmw8.sub_u",
    "i32.atomic.rmw16.sub_u",
    "i64.atomic.rmw.sub",
    "i64.atomic.rmw8.sub_u",
    "i64.atomic.rmw16.sub_u",
    "i64.atomic.rmw32.sub_u",
    "i32.atomic.rmw.and",
    "i32.atomic.rmw8.and_u",
    "i32.atomic.rmw16.and_u",
    "i64.atomic.rmw.and",
    "i64.atomic.rmw8.and_u",
    "i64.atomic.rmw16.and_u",
    "i64.atomic.rmw32.and_u",
    "i32.atomic.rmw.or",
    "i32.atomic.rmw8.or_u",
    "i32.atomic.rmw16.or_u",
    "i64.atomic.rmw.or",
    "i64.atomic.rmw8.or_u",
    "i64.atomic.rmw16.or_u",
    "i64.atomic.rmw32.or_u",
    "i32.atomic.rmw.xor",
    "i32.atomic.rmw8.xor_u",
    "i32.atomic.rmw16.xor_u",
    "i64.atomic.rmw.xor",
    "i64.atomic.rmw8.xor_u",
    "i64.atomic.rmw16.xor_u",
    "i64.atomic.rmw32.xor_u",
    "i32.atomic.rmw.xchg",
    "i32.atomic.rmw8.xchg_u",
    "i32.atomic.rmw16.xchg_u",
    "i64.atomic.rmw.xchg",
    "i64.atomic.rmw8.xchg_u",
    "i64.atomic.rmw16.xchg_u",
    "i64.atomic.rmw32.xchg_u",
    "i32.atomic.rmw.cmpxchg",
    "i32.atomic.rmw8.cmpxchg_u",
    "i32.atomic.rmw16.cmpxchg_u",
    "i64.atomic.rmw.cmpxchg",
    "i64.atomic.rmw8.cmpxchg_u",
    "i64.atomic.rmw16.cmpxchg_u",
    "i64.atomic.rmw32.cmpxchg_u",
];

#[test]
fn every_linear_memory_atomic_opcode_executes_like_wasmtime() {
    let mut absent: Vec<&str> = Vec::new();
    for mnemonic in EVERY_LINEAR_MEMORY_ATOMIC {
        if !ATOMICS_EVERY_OPCODE_DIFF.contains(mnemonic) {
            absent.push(mnemonic);
        }
    }
    assert!(
        absent.is_empty(),
        "{}/{} threads-proposal linear-memory atomics are graded; the fixture is missing \
         {absent:?}",
        EVERY_LINEAR_MEMORY_ATOMIC.len() - absent.len(),
        EVERY_LINEAR_MEMORY_ATOMIC.len()
    );
    grade(&Spec {
        label: "atomics_every_opcode",
        wat: ATOMICS_EVERY_OPCODE_DIFF,
        configure: atomics_config,
        langs: &ALL_LANGS,
        min_exports: 70,
        ungraded: &[],
        refused: &[],
        battery: &BATTERY,
    });
}

#[test]
fn lifted_targets_block_and_report_wait_and_notify_like_wasmtime() {
    grade(&Spec {
        label: "atomics_wait_notify",
        wat: ATOMICS_WAIT_NOTIFY_DIFF,
        configure: atomics_config,
        langs: &ALL_LANGS,
        min_exports: 13,
        ungraded: &[],
        refused: &[],
        battery: &BATTERY,
    });
}

#[test]
fn lifted_targets_trap_misaligned_atomics_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_misaligned",
            wat: ATOMICS_MISALIGNED_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-unaligned",
        Trap::HeapMisaligned,
    );
}

#[test]
fn lifted_targets_trap_aligned_atomic_oob_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_aligned_oob",
            wat: ATOMICS_ALIGNED_OOB_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-oob",
        Trap::MemoryOutOfBounds,
    );
}

#[test]
fn lifted_targets_trap_atomic_effective_address_overflow_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_address_overflow",
            wat: ATOMICS_ADDRESS_OVERFLOW_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-oob",
        Trap::MemoryOutOfBounds,
    );
}

#[test]
fn lifted_targets_trap_memory64_overflowing_misalignment_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_memory64_overflow_misaligned",
            wat: ATOMICS_MEMORY64_OVERFLOW_MISALIGNED_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-unaligned",
        Trap::HeapMisaligned,
    );
}

#[test]
fn lifted_targets_trap_aligned_memory64_2pow53_offset_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_memory64_aligned_offset_2pow53",
            wat: ATOMICS_MEMORY64_ALIGNED_OFFSET_2POW53_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-oob",
        Trap::MemoryOutOfBounds,
    );
}

#[test]
fn lifted_targets_trap_memory64_uint64_max_offset_like_wasmtime() {
    grade_traps(
        &Spec {
            label: "atomics_memory64_uint64_max_offset",
            wat: ATOMICS_MEMORY64_UINT64_MAX_OFFSET_DIFF,
            configure: atomics_config,
            langs: &ALL_LANGS,
            min_exports: 1,
            ungraded: &[],
            refused: &[],
            battery: &[],
        },
        "DR-WASMDEOB-TRAP/1:atomic-oob",
        Trap::MemoryOutOfBounds,
    );
}

#[test]
fn trap_contract_rejects_the_wrong_atomic_trap_kind() {
    let expected_marker: &str = "DR-WASMDEOB-TRAP/1:atomic-unaligned";
    exec_diff::validate_trap_contract(
        false,
        b"",
        format!("{expected_marker}\n").as_bytes(),
        expected_marker,
    )
    .expect("the exact trap marker satisfies the contract");
    let wrong_marker: &str = "DR-WASMDEOB-TRAP/1:atomic-oob";
    assert!(
        exec_diff::validate_trap_contract(
            false,
            b"",
            format!("{wrong_marker}\n").as_bytes(),
            expected_marker,
        )
        .is_err(),
        "the trap validator must reject an OOB marker when Wasmtime reported misalignment"
    );
}

#[test]
fn output_comparator_rejects_corrupted_and_unexpected_values() {
    let expected: Vec<(String, Option<i32>)> = vec![("value 1".to_owned(), Some(7))];
    let mut actual: BTreeMap<String, i32> = BTreeMap::new();
    actual.insert("value 1".to_owned(), 8);
    actual.insert("unexpected 1".to_owned(), 7);
    let divergences: Vec<String> = exec_diff::output_divergences(&expected, &actual, "wasmtime");
    assert_eq!(
        divergences.len(),
        2,
        "the comparator must reject a corrupt value and an unexpected output key"
    );
}

#[test]
fn lifted_targets_execute_narrow_atomic_cmpxchg_like_wasmtime() {
    grade(&Spec {
        label: "atomics_narrow_cmpxchg",
        wat: ATOMICS_NARROW_CMPXCHG_DIFF,
        configure: atomics_config,
        langs: &ALL_LANGS,
        min_exports: 5,
        ungraded: &[],
        refused: &[],
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
        refused: &[],
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
        refused: &[],
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
        refused: &[],
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
        refused: &[],
        battery: &NON_TRAPPING_BATTERY,
    });
}
