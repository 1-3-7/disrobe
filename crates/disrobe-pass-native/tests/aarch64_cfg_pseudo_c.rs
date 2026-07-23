#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{Error, LeafRecovery, recover_aarch64_function};

#[test]
fn signed_nzcv_join_diamond_passes_cfg_edge_guard_without_goto() {
    let bytes: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6c, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x00,
        0x14, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("signed nzcv diamond");

    assert!(recovered.source.contains("if ("), "{}", recovered.source);
    assert!(recovered.source.contains("else"), "{}", recovered.source);
    assert!(recovered.source.contains(" > "), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    let else_index: usize = recovered.source.find("else").expect("else branch");
    let return_index: usize = recovered
        .source
        .rfind("return r_rax;")
        .expect("joined return");
    assert!(else_index < return_index, "{}", recovered.source);
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    if ((int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1)) {\n        r_rax = (uint64_t)(int64_t)2LL;\n    } else {\n        r_rax = (uint64_t)(int64_t)1LL;\n    }\n    return r_rax;\n}\n";
    assert_eq!(recovered.source, expected);
}

#[test]
fn pure_short_circuit_and_emits_fused_nzcv_condition_without_goto() {
    let bytes: [u8; 32] = [
        0x1f, 0x00, 0x01, 0xeb, 0xad, 0x00, 0x00, 0x54, 0x5f, 0x00, 0x03, 0xeb, 0x6a, 0x00, 0x00,
        0x54, 0x20, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x00, 0x14, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03,
        0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("pure short-circuit and");

    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_x2 = a2;\n    uint64_t r_a64_x3 = a3;\n    if (((int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1)) && ((int64_t)(int64_t)(r_a64_x2) < (int64_t)(int64_t)(r_a64_x3))) {\n        r_rax = (uint64_t)(int64_t)1LL;\n    } else {\n        r_rax = (uint64_t)(int64_t)2LL;\n    }\n    return r_rax;\n}\n";

    assert_eq!(recovered.source, expected);
}

#[test]
fn pure_short_circuit_or_emits_fused_nzcv_condition_without_goto() {
    let bytes: [u8; 36] = [
        0x1f, 0x00, 0x01, 0xeb, 0x8c, 0x00, 0x00, 0x54, 0x5f, 0x00, 0x03, 0xeb, 0x4b, 0x00, 0x00,
        0x54, 0x03, 0x00, 0x00, 0x14, 0x20, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x00, 0x14, 0x40, 0x00,
        0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("pure short-circuit or");

    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_x2 = a2;\n    uint64_t r_a64_x3 = a3;\n    if (((int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1)) || ((int64_t)(int64_t)(r_a64_x2) < (int64_t)(int64_t)(r_a64_x3))) {\n        r_rax = (uint64_t)(int64_t)1LL;\n    } else {\n        r_rax = (uint64_t)(int64_t)2LL;\n    }\n    return r_rax;\n}\n";

    assert_eq!(recovered.source, expected);
}

#[test]
fn impure_second_predicate_does_not_emit_a_fused_short_circuit_if() {
    let bytes: [u8; 36] = [
        0x1f, 0x00, 0x01, 0xeb, 0xcd, 0x00, 0x00, 0x54, 0x20, 0x00, 0x00, 0xf9, 0x5f, 0x00, 0x03,
        0xeb, 0x6a, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x00, 0x14, 0x40, 0x00,
        0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("impure second predicate");
    let if_count: usize = recovered.source.match_indices("if (").count();

    assert_ne!(if_count, 1, "{}", recovered.source);
    assert!(!recovered.source.contains("&&"), "{}", recovered.source);
    assert!(!recovered.source.contains("||"), "{}", recovered.source);
}

#[test]
fn assigned_second_predicate_does_not_emit_a_fused_short_circuit_if() {
    let bytes: [u8; 36] = [
        0x1f, 0x00, 0x01, 0xeb, 0xcd, 0x00, 0x00, 0x54, 0xe4, 0x03, 0x00, 0xaa, 0x5f, 0x00, 0x03,
        0xeb, 0x6a, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x00, 0x14, 0x40, 0x00,
        0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("assigned second predicate");
    let if_count: usize = recovered.source.match_indices("if (").count();

    assert_ne!(if_count, 1, "{}", recovered.source);
    assert!(!recovered.source.contains("&&"), "{}", recovered.source);
    assert!(!recovered.source.contains("||"), "{}", recovered.source);
    let first_condition: &str = "if ((int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1)) {";
    let condition_index: usize = recovered
        .source
        .find(first_condition)
        .expect("first predicate guard");
    let assignment_index: usize = recovered
        .source
        .find("r_a64_x4 = r_rax;")
        .expect("second predicate assignment");

    assert!(condition_index < assignment_index, "{}", recovered.source);
}

#[test]
fn branchless_add_keeps_the_pre_cfg_c_output() {
    let bytes: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("branchless add");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_x2 = a2;\n    uint64_t r_a64_tmp = 0;\n    uint64_t r_a64_x8 = 0;\n    r_a64_tmp = r_a64_x1;\n    r_a64_tmp = r_a64_tmp + (r_rax);\n    r_a64_x8 = r_a64_tmp;\n    r_a64_tmp = r_a64_x8;\n    r_a64_tmp = r_a64_tmp + (r_a64_x2);\n    r_rax = r_a64_tmp;\n    return r_rax;\n}\n";

    assert_eq!(recovered.source, expected);
}

#[test]
fn pre_tested_counting_loop_uses_cfg_while_without_goto() {
    let bytes: [u8; 20] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6a, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfd, 0xff, 0xff,
        0x17, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("pre-tested loop");
    let condition: &str = "while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1)) {";

    assert!(recovered.source.contains(condition), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn pre_tested_loop_header_operands_remain_parameters_after_body_overwrite() {
    let bytes: [u8; 20] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6a, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xfd, 0xff, 0xff,
        0x17, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("header parameter ordering");

    assert_eq!(recovered.params.len(), 2, "{:?}", recovered.params);
    assert!(
        recovered
            .source
            .contains("uint64_t recovered(uint64_t a0, uint64_t a1)"),
        "{}",
        recovered.source
    );
}

#[test]
fn post_tested_counting_loop_uses_cfg_do_while_without_goto() {
    let bytes: [u8; 20] = [
        0x01, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x01, 0xeb, 0xab, 0xff, 0xff,
        0x54, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("post-tested loop");
    let condition: &str = "} while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1));";

    assert!(recovered.source.contains("do {"), "{}", recovered.source);
    assert!(recovered.source.contains(condition), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn post_tested_loop_header_back_edge_falls_back_from_cfg_structuring() {
    let bytes: [u8; 32] = [
        0x01, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02, 0xeb, 0xa0, 0xff, 0xff,
        0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x01, 0xeb, 0x4b, 0xff, 0xff, 0x54, 0xc0, 0x03,
        0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("header-edge fallback");

    assert!(
        recovered.source.contains("while (1)"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("do {"), "{}", recovered.source);
}

#[test]
fn post_tested_loop_mid_body_exit_emits_break_without_goto() {
    let bytes: [u8; 36] = [
        0x01, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02, 0xeb, 0xa0, 0x00, 0x00,
        0x54, 0x00, 0x04, 0x00, 0x91, 0x01, 0x00, 0x00, 0x14, 0x1f, 0x00, 0x01, 0xeb, 0x2b, 0xff,
        0xff, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("post-tested break");
    let condition: &str = "} while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1));";
    let break_condition: &str = "if ((int64_t)(int64_t)(r_rax) == (int64_t)(int64_t)(r_a64_x2)) {";

    assert!(recovered.source.contains("do {"), "{}", recovered.source);
    assert!(recovered.source.contains(condition), "{}", recovered.source);
    assert!(
        recovered.source.contains(break_condition),
        "{}",
        recovered.source
    );
    assert!(recovered.source.contains("break;"), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    let rust_source: &str = recovered
        .rust_source
        .as_deref()
        .expect("post-tested break rust source");

    assert!(!rust_source.contains("continue;"), "{rust_source}");
}

#[test]
fn post_tested_loop_mid_body_latch_edge_falls_back_from_cfg_structuring() {
    let bytes: [u8; 36] = [
        0x01, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02, 0xeb, 0x60, 0x00, 0x00,
        0x54, 0x00, 0x04, 0x00, 0x91, 0x01, 0x00, 0x00, 0x14, 0x1f, 0x00, 0x01, 0xeb, 0x2b, 0xff,
        0xff, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("post-tested fallback");

    assert!(
        recovered.source.contains("while (1)"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("do {"), "{}", recovered.source);
}

#[test]
fn nested_pre_tested_loops_render_innermost_first_without_goto() {
    let bytes: [u8; 28] = [
        0x1f, 0x00, 0x01, 0xeb, 0xaa, 0x00, 0x00, 0x54, 0x5f, 0x00, 0x03, 0xeb, 0xaa, 0xff, 0xff,
        0x54, 0x42, 0x04, 0x00, 0x91, 0xfd, 0xff, 0xff, 0x17, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("nested loops");
    let outer: &str = "while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1)) {";
    let inner: &str = "while ((int64_t)(int64_t)(r_a64_x2) < (int64_t)(int64_t)(r_a64_x3)) {";
    let outer_index: usize = recovered.source.find(outer).expect("outer while");
    let inner_index: usize = recovered.source.find(inner).expect("inner while");

    assert_eq!(
        recovered.source.match_indices("while (").count(),
        2,
        "{}",
        recovered.source
    );
    assert!(outer_index < inner_index, "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn pre_tested_loop_mid_body_exit_emits_break_without_goto() {
    let bytes: [u8; 32] = [
        0x1f, 0x00, 0x01, 0xeb, 0xca, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02,
        0xeb, 0x60, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0xc0, 0x03,
        0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("mid-body break");
    let loop_condition: &str = "while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1)) {";
    let break_condition: &str = "if ((int64_t)(int64_t)(r_rax) == (int64_t)(int64_t)(r_a64_x2)) {";

    assert!(
        recovered.source.contains(loop_condition),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains(break_condition),
        "{}",
        recovered.source
    );
    assert!(recovered.source.contains("break;"), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn pre_tested_loop_mid_body_back_edge_emits_continue_without_goto() {
    let bytes: [u8; 32] = [
        0x1f, 0x00, 0x01, 0xeb, 0xca, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02,
        0xeb, 0x80, 0xff, 0xff, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0xc0, 0x03,
        0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("mid-body continue");
    let loop_condition: &str = "while ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1)) {";
    let continue_condition: &str =
        "if ((int64_t)(int64_t)(r_rax) == (int64_t)(int64_t)(r_a64_x2)) {";

    assert!(
        recovered.source.contains(loop_condition),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains(continue_condition),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("continue;"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn loop_with_distinct_mid_body_exit_targets_falls_back_from_cfg_structuring() {
    let bytes: [u8; 36] = [
        0x1f, 0x00, 0x01, 0xeb, 0xea, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02,
        0xeb, 0x60, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0xc0, 0x03,
        0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let result: Result<LeafRecovery, Error> = recover_aarch64_function(&bytes, 0);

    assert!(result.is_err(), "distinct exits must fall back");
}

#[test]
fn multi_entry_loop_structures_without_goto_via_cns() {
    let bytes: [u8; 20] = [
        0x40, 0x00, 0x00, 0xb4, 0x02, 0x00, 0x00, 0x14, 0xff, 0xff, 0xff, 0x17, 0xe0, 0xff, 0xff,
        0xb5, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("multi-entry loop");

    assert!(
        recovered.source.contains("while (1)"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    assert!(!recovered.source.contains("do {"), "{}", recovered.source);
}

#[test]
fn conflicting_nzcv_definitions_fall_back_without_structuring() {
    let bytes: [u8; 40] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6c, 0x00, 0x00, 0x54, 0x1f, 0x00, 0x02, 0xeb, 0x02, 0x00, 0x00,
        0x14, 0x1f, 0x00, 0x03, 0xeb, 0x6c, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03,
        0x5f, 0xd6, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let result: Result<LeafRecovery, Error> = recover_aarch64_function(&bytes, 0);
    let error: Error = result.expect_err("conflicting nzcv must reject");
    match error {
        Error::LlvmIr(message) => {
            assert_eq!(
                message,
                "aarch64 reject: conditional branch lacks live nzcv state"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
