#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::pseudo_c::{
    recover_aarch64_function, recover_aarch64_function_with_image,
};
use disrobe_pass_native::{Error, LeafRecovery};

const BASE: u64 = 0x10000;
const TABLE_VA: u64 = 0x20000;
const SWITCH_BYTES: [u8; 64] = [
    0x1f, 0x08, 0x00, 0x71, 0xa8, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91,
    0x22, 0x48, 0x60, 0x38, 0x63, 0x00, 0x00, 0x10, 0x64, 0x88, 0x22, 0x8b, 0x80, 0x00, 0x1f, 0xd6,
    0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
];

const LOWER_BOUND_SWITCH_BYTES: [u8; 68] = [
    0x01, 0x28, 0x00, 0x51, 0x3f, 0x08, 0x00, 0x71, 0xa8, 0x01, 0x00, 0x54, 0x82, 0x00, 0x00, 0x90,
    0x42, 0x00, 0x00, 0x91, 0x43, 0x48, 0x61, 0x38, 0x64, 0x00, 0x00, 0x10, 0x85, 0x88, 0x23, 0x8b,
    0xa0, 0x00, 0x1f, 0xd6, 0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6,
];

const IN_PLACE_LOWER_BOUND_SWITCH_BYTES: [u8; 68] = [
    0x00, 0x28, 0x00, 0x51, 0x1f, 0x08, 0x00, 0x71, 0xa8, 0x01, 0x00, 0x54, 0x82, 0x00, 0x00, 0x90,
    0x42, 0x00, 0x00, 0x91, 0x43, 0x48, 0x60, 0x38, 0x64, 0x00, 0x00, 0x10, 0x85, 0x88, 0x23, 0x8b,
    0xa0, 0x00, 0x1f, 0xd6, 0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6,
];

const HALFWORD_SWITCH_BYTES: [u8; 64] = [
    0x1f, 0x08, 0x00, 0x71, 0xa8, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91,
    0x22, 0x58, 0x60, 0x78, 0x63, 0x00, 0x00, 0x10, 0x64, 0xa8, 0x22, 0x8b, 0x80, 0x00, 0x1f, 0xd6,
    0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
];

const WORD_SWITCH_BYTES: [u8; 64] = [
    0x1f, 0x08, 0x00, 0x71, 0xa8, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91,
    0x22, 0x58, 0xa0, 0xb8, 0xe3, 0x00, 0x00, 0x10, 0x64, 0xc8, 0x22, 0x8b, 0x80, 0x00, 0x1f, 0xd6,
    0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
];

const UNPROVEN_ABSOLUTE_SWITCH_BYTES: [u8; 56] = [
    0x1f, 0x08, 0x00, 0x71, 0x68, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91,
    0x24, 0x78, 0x60, 0xf8, 0x80, 0x00, 0x1f, 0xd6, 0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    0x60, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    0xa0, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
];

const ABSOLUTE_SWITCH_BYTES: [u8; 60] = [
    0x00, 0x00, 0x00, 0x51, 0x1f, 0x08, 0x00, 0x71, 0x68, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90,
    0x21, 0x00, 0x00, 0x91, 0x24, 0x78, 0x60, 0xf8, 0x80, 0x00, 0x1f, 0xd6, 0x40, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
];

const NONZERO_CASE_MINIMUM_SWITCH_BYTES: [u8; 68] = [
    0x00, 0x28, 0x00, 0x51, 0x1f, 0x0c, 0x00, 0x71, 0xa2, 0x01, 0x00, 0x54, 0x81, 0x00, 0x00, 0x90,
    0x21, 0x00, 0x00, 0x91, 0x22, 0x58, 0x60, 0x78, 0x63, 0x00, 0x00, 0x10, 0x64, 0xa8, 0x22, 0x8b,
    0x80, 0x00, 0x1f, 0xd6, 0x40, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x60, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6, 0x80, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52,
    0xc0, 0x03, 0x5f, 0xd6,
];

fn assert_switch_cases(recovered: &LeafRecovery, labels: &[i64]) {
    assert!(
        recovered.source.contains("switch ("),
        "{}",
        recovered.source
    );
    for label in labels {
        assert!(
            recovered.source.contains(&format!("case {label}:")),
            "{}",
            recovered.source
        );
    }
    assert!(
        recovered.source.contains("default:"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    assert!(recovered.lifted_switch, "{}", recovered.source);
}

#[test]
fn aarch64_relative_byte_switch_uses_the_image_table() {
    let table: [u8; 3] = [0, 2, 4];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("relative byte switch");

    assert!(
        recovered.source.contains("switch ("),
        "{}",
        recovered.source
    );
    assert!(recovered.source.contains("case 0:"), "{}", recovered.source);
    assert!(recovered.source.contains("case 1:"), "{}", recovered.source);
    assert!(recovered.source.contains("case 2:"), "{}", recovered.source);
    assert!(
        recovered.source.contains("default:"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    assert!(recovered.lifted_switch, "{}", recovered.source);
}

#[test]
fn aarch64_relative_byte_switch_groups_duplicate_case_targets() {
    let table: [u8; 3] = [0, 0, 4];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("relative byte switch with duplicate targets");

    assert!(recovered.source.contains("case 0:"), "{}", recovered.source);
    assert!(recovered.source.contains("case 1:"), "{}", recovered.source);
    assert_eq!(
        recovered
            .source
            .matches("r_rax = ((uint64_t)(int64_t)10LL)")
            .count(),
        1,
        "{}",
        recovered.source
    );
}

#[test]
fn aarch64_relative_byte_switch_preserves_a_distinct_lower_bound_selector() {
    let table: [u8; 3] = [0, 2, 4];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &LOWER_BOUND_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("lower-bound relative byte switch");

    assert!(
        recovered.source.contains("switch (r_rax)"),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("case 10:"),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("case 11:"),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("case 12:"),
        "{}",
        recovered.source
    );
    assert!(
        !recovered.source.contains("r_a64_tmp ="),
        "{}",
        recovered.source
    );
}

#[test]
fn aarch64_relative_byte_switch_preserves_an_in_place_lower_bound_selector() {
    let table: [u8; 3] = [0, 2, 4];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &IN_PLACE_LOWER_BOUND_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("in-place lower-bound relative byte switch");

    assert_switch_cases(&recovered, &[10, 11, 12]);
}

#[test]
fn aarch64_relative_halfword_switch_uses_the_image_table() {
    let table: [u8; 6] = [0, 0, 2, 0, 4, 0];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &HALFWORD_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("relative halfword switch");

    assert_switch_cases(&recovered, &[0, 1, 2]);
}

#[test]
fn aarch64_relative_word_switch_uses_the_image_table() {
    let table: [u8; 12] = [0xfc, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0, 0, 0, 0];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &WORD_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("relative word switch");

    assert_switch_cases(&recovered, &[0, 1, 2]);
}

#[test]
fn aarch64_absolute_switch_uses_the_image_table() {
    let table: [u8; 24] = [
        0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &ABSOLUTE_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("absolute switch");

    assert_switch_cases(&recovered, &[0, 1, 2]);
}

#[test]
fn aarch64_pie_absolute_switch_uses_the_relocation_table() {
    let table: [u8; 24] = [0; 24];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &ABSOLUTE_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|address: u64| match address {
            TABLE_VA => Some(BASE + 0x1c),
            value if value == TABLE_VA + 8 => Some(BASE + 0x24),
            value if value == TABLE_VA + 16 => Some(BASE + 0x2c),
            _ => None,
        },
    )
    .expect("pie absolute switch");

    assert_switch_cases(&recovered, &[0, 1, 2]);
}

#[test]
fn aarch64_relative_switch_uses_a_nonzero_case_minimum_with_an_hs_guard() {
    let table: [u8; 6] = [0, 0, 2, 0, 4, 0];
    let recovered: LeafRecovery = recover_aarch64_function_with_image(
        &NONZERO_CASE_MINIMUM_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    )
    .expect("nonzero case minimum switch");

    assert_switch_cases(&recovered, &[10, 11, 12]);
}

#[test]
fn aarch64_pie_absolute_switch_with_an_unresolved_zero_entry_falls_back() {
    let table: [u8; 24] = [0; 24];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &ABSOLUTE_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|address: u64| match address {
            TABLE_VA => Some(BASE + 0x1c),
            value if value == TABLE_VA + 8 => Some(BASE + 0x24),
            _ => None,
        },
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_absolute_switch_with_an_external_target_falls_back() {
    let table: [u8; 24] = [
        0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &ABSOLUTE_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_absolute_switch_requires_a_zero_extended_index() {
    let table: [u8; 24] = [
        0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &UNPROVEN_ABSOLUTE_SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_switch_rejects_an_anchor_that_overwrites_the_selector() {
    let mut bytes: [u8; 68] = NONZERO_CASE_MINIMUM_SWITCH_BYTES;
    bytes[..8].copy_from_slice(&[0x09, 0x28, 0x00, 0x51, 0x3f, 0x09, 0x00, 0x71]);
    bytes[20..24].copy_from_slice(&[0x22, 0x58, 0x69, 0x78]);
    bytes[24..32].copy_from_slice(&[0x60, 0x00, 0x00, 0x10, 0x04, 0xa8, 0x22, 0x8b]);
    let table: [u8; 6] = [0, 0, 2, 0, 4, 0];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &bytes,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_switch_rejects_an_offset_that_overwrites_the_selector() {
    let mut bytes: [u8; 68] = NONZERO_CASE_MINIMUM_SWITCH_BYTES;
    bytes[..8].copy_from_slice(&[0x09, 0x28, 0x00, 0x51, 0x3f, 0x09, 0x00, 0x71]);
    bytes[20..24].copy_from_slice(&[0x20, 0x58, 0x69, 0x78]);
    bytes[28..32].copy_from_slice(&[0x64, 0xa8, 0x20, 0x8b]);
    let table: [u8; 6] = [0, 0, 2, 0, 4, 0];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &bytes,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_switch_rejects_a_guard_target_inside_the_dispatch() {
    let mut bytes: [u8; 64] = HALFWORD_SWITCH_BYTES;
    bytes[4..8].copy_from_slice(&[0x68, 0x00, 0x00, 0x54]);
    let table: [u8; 6] = [0, 0, 2, 0, 4, 0];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &bytes,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_byte_switch_rejects_a_target_outside_the_function() {
    let table: [u8; 3] = [0, 2, 0x40];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &SWITCH_BYTES,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_byte_switch_requires_the_dominating_range_guard() {
    let mut bytes: [u8; 64] = SWITCH_BYTES;
    bytes[..8].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5]);
    let table: [u8; 3] = [0, 2, 4];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &bytes,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_relative_byte_switch_rejects_a_table_base_that_overwrites_the_selector() {
    let mut bytes: [u8; 64] = SWITCH_BYTES;
    bytes[8..20].copy_from_slice(&[
        0x80, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0x00, 0x48, 0x60, 0x38,
    ]);
    let table: [u8; 3] = [0, 2, 4];
    let result: Result<LeafRecovery, Error> = recover_aarch64_function_with_image(
        &bytes,
        BASE,
        &|address: u64| (address == TABLE_VA).then_some(table.as_slice()),
        &|_: u64| None,
    );

    assert!(result.is_err(), "{result:?}");
}

#[test]
fn aarch64_recovery_without_an_image_keeps_existing_output_byte_identical() {
    let bytes: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let existing: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("existing recovery");
    let image_aware: LeafRecovery =
        recover_aarch64_function_with_image(&bytes, 0, &|_: u64| None, &|_: u64| None)
            .expect("image-aware recovery");

    assert_eq!(image_aware, existing);
}
