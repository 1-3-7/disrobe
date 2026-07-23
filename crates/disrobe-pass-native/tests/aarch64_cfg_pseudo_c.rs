#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{Error, LeafRecovery, recover_aarch64_function};

#[test]
fn aarch64_real_clang_framed_loop_function_recovers_end_to_end() {
    let bytes: [u8; 108] = [
        0xfd, 0x7b, 0xbd, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x03, 0x00,
        0x91, 0x3f, 0x04, 0x00, 0x71, 0xf3, 0x03, 0x00, 0x2a, 0xeb, 0x01, 0x00, 0x54, 0xf4, 0x03,
        0x01, 0x2a, 0xf5, 0x03, 0x1f, 0x2a, 0xf6, 0x03, 0x1f, 0x2a, 0xe0, 0x03, 0x13, 0x2a, 0xe1,
        0x03, 0x15, 0x2a, 0x00, 0x00, 0x00, 0x94, 0xb5, 0x06, 0x00, 0x11, 0x16, 0x00, 0x16, 0x0b,
        0x9f, 0x02, 0x15, 0x6b, 0x41, 0xff, 0xff, 0x54, 0xc8, 0x7e, 0xb6, 0x0a, 0xc9, 0x92, 0x01,
        0x71, 0x28, 0xc1, 0x88, 0x1a, 0x02, 0x00, 0x00, 0x14, 0xe8, 0x03, 0x1f, 0x2a, 0x00, 0x01,
        0x13, 0x0b, 0xf4, 0x4f, 0x42, 0xa9, 0xf6, 0x57, 0x41, 0xa9, 0xfd, 0x7b, 0xc3, 0xa8, 0xc0,
        0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("framed loop function recovers");
    assert!(r.source.contains("sub_30("), "{}", r.source);
    assert!(r.source.contains("while (1)"), "{}", r.source);
    assert!(r.source.contains("break;"), "{}", r.source);
    assert!(r.source.contains("~r_a64_tmp2"), "{}", r.source);
    assert!(r.source.contains(" ? "), "{}", r.source);
    assert!(!r.source.contains("goto"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_adrp_materializes_a_page_address_for_a_global_load() {
    let bytes: [u8; 12] = [
        0x08, 0x00, 0x00, 0x90, 0x00, 0x01, 0x40, 0xb9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0x0021_0000).expect("adrp global load");
    assert!(r.source.contains("2162688LL"), "{}", r.source);
    assert!(r.source.contains("*(uint32_t*)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_ror_recovers_as_a_shift_or_rotate() {
    let bytes: [u8; 12] = [
        0xe8, 0x03, 0x01, 0x4b, 0x00, 0x2c, 0xc8, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ror rotate");
    assert!(r.source.matches("& 31))").count() >= 2, "{}", r.source);
    assert!(r.source.contains("| (r_a64_tmp)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_paired_struct_load_recovers_two_fields() {
    let bytes: [u8; 12] = [
        0x08, 0x24, 0x40, 0x29, 0x20, 0x01, 0x08, 0x0b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("paired struct load");
    assert!(
        r.source.contains("*(uint32_t*)(uintptr_t)(r_rax)"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(r_rax + (uint64_t)(int64_t)4LL)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_vector_compare_to_zero_recovers_as_elementwise_eq() {
    let bytes: [u8; 8] = [0x00, 0x98, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector cmeq zero");
    assert!(r.source.contains("v0 = v0 == 0"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_vector_compare_registers_recovers_as_elementwise_eq() {
    let bytes: [u8; 8] = [0x00, 0x8c, 0xa1, 0x6e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector cmeq reg");
    assert!(r.source.contains("v0 = v0 == v1"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_vector_movi_broadcasts_a_word_immediate() {
    let bytes: [u8; 8] = [0x20, 0x04, 0x00, 0x4f, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector movi word");
    assert!(
        r.source
            .contains("{(int32_t)1, (int32_t)1, (int32_t)1, (int32_t)1}"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_vector_movi_broadcasts_a_zero_doubleword() {
    let bytes: [u8; 8] = [0x00, 0xe4, 0x00, 0x6f, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector movi zero");
    assert!(
        r.source.contains("{(int64_t)0, (int64_t)0}"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_vector_and_recovers_as_elementwise_and() {
    let bytes: [u8; 8] = [0x20, 0x1c, 0x20, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector and");
    assert!(r.source.contains("v0 = v1 & v0"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_vector_add_recovers_as_elementwise_add() {
    let bytes: [u8; 8] = [0x20, 0x84, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector add");
    assert!(r.source.contains("v0 = v1 + v0"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_neg_negates() {
    let bytes: [u8; 8] = [0xe0, 0x03, 0x00, 0x4b, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("neg");
    assert!(r.source.contains("-(int64_t)r_rax"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_cneg_recovers_absolute_value() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x00, 0x71, 0x00, 0x54, 0x80, 0x5a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cneg absval");
    assert!(r.source.contains("-(int64_t)r_a64_tmp2"), "{}", r.source);
    assert!(r.source.contains("< 0 ? (r_a64_tmp2)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_cinc_conditionally_increments() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0x40, 0xc4, 0x82, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cinc");
    assert!(
        r.source.contains("r_a64_tmp2 + ((uint64_t)(int64_t)1LL)"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("sel_cc_0 != 0 ? (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_cinv_conditionally_inverts() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0x40, 0xc0, 0x82, 0x5a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cinv");
    assert!(r.source.contains("(~r_a64_tmp2)"), "{}", r.source);
    assert!(
        r.source.contains("sel_cc_0 != 0 ? (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_cneg_conditionally_negates() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0x40, 0xc4, 0x82, 0x5a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cneg");
    assert!(r.source.contains("-(int64_t)r_a64_tmp2"), "{}", r.source);
    assert!(
        r.source.contains("sel_cc_0 != 0 ? (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_csetm_sets_all_ones_or_zero() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0xe0, 0xd3, 0x9f, 0x5a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("csetm");
    assert!(
        r.source
            .contains("sel_cc_0 != 0 ? ((uint64_t)(int64_t)-1LL)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_bic_is_and_not() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x21, 0x0a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("bic");
    assert!(r.source.contains("~r_a64_tmp2"), "{}", r.source);
    assert!(
        r.source.contains("r_a64_tmp & (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_orn_is_or_not() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x21, 0x2a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("orn");
    assert!(r.source.contains("~r_a64_tmp2"), "{}", r.source);
    assert!(
        r.source.contains("r_a64_tmp | (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_eon_is_xor_not() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x21, 0x4a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("eon");
    assert!(r.source.contains("~r_a64_tmp2"), "{}", r.source);
    assert!(
        r.source.contains("r_a64_tmp ^ (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_bic_with_asr_shift_recovers_clamp_to_zero() {
    let bytes: [u8; 8] = [0x00, 0x7c, 0xa0, 0x0a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("bic asr");
    assert!(r.source.contains("~r_a64_tmp2"), "{}", r.source);
    assert!(r.source.contains(">>"), "{}", r.source);
    assert!(
        r.source.contains("r_a64_tmp & (r_a64_tmp2)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_ldrb_zero_extends_a_byte() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x40, 0x39, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrb");
    assert!(r.source.contains("*(uint8_t*)"), "{}", r.source);
    assert!(r.source.contains("(uint8_t)"), "{}", r.source);
    assert!(!r.source.contains("(int8_t)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_ldrsb_sign_extends_a_byte() {
    let bytes: [u8; 8] = [0x00, 0x00, 0xc0, 0x39, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrsb");
    assert!(r.source.contains("*(uint8_t*)"), "{}", r.source);
    assert!(r.source.contains("(int8_t)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_ldrh_zero_extends_a_halfword() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x40, 0x79, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrh");
    assert!(r.source.contains("*(uint16_t*)"), "{}", r.source);
    assert!(r.source.contains("(uint16_t)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_ldrsw_sign_extends_a_word_to_64_bits() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x80, 0xb9, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrsw");
    assert!(r.source.contains("*(uint32_t*)"), "{}", r.source);
    assert!(r.source.contains("(int64_t)(int32_t)"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_unscaled_load_recovers_as_a_load() {
    let bytes: [u8; 8] = [0x00, 0xc0, 0x5f, 0xb8, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldur");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0) {\n    uint64_t r_rax = a0;\n    r_rax = ((uint64_t)(*(uint32_t*)(uintptr_t)(r_rax + (uint64_t)(int64_t)-4LL))) & 0xffffffffULL;\n    return (r_rax) & 0xffffffffULL;\n}\n";
    assert_eq!(recovered.source, expected);
}

#[test]
fn aarch64_real_clang_unscaled_store_recovers_as_a_store() {
    let bytes: [u8; 8] = [0x01, 0xc0, 0x1f, 0xb8, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("stur");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    (*(uint32_t*)(uintptr_t)(r_rax + (uint64_t)(int64_t)-4LL)) = (r_a64_x1) & 0xffffffffULL;\n    return r_rax;\n}\n";
    assert_eq!(recovered.source, expected);
}

#[test]
fn aarch64_real_clang_csel_max_recovers_as_ternary() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0x00, 0xc0, 0x81, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("csel max");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    r_rax = (int64_t)(int32_t)(r_rax) <= (int64_t)(int32_t)(r_a64_x1) ? (r_a64_x1) & 0xffffffffULL : r_rax;\n    return (r_rax) & 0xffffffffULL;\n}\n";
    assert_eq!(recovered.source, expected);
}

#[test]
fn aarch64_real_clang_three_register_csel_recovers_as_ternary() {
    let bytes: [u8; 16] = [
        0x1f, 0x00, 0x01, 0x6b, 0x48, 0xc0, 0x83, 0x1a, 0x00, 0x01, 0x04, 0x0b, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("three-register csel");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_x2 = a2;\n    uint64_t r_a64_x3 = a3;\n    uint64_t r_a64_x4 = a4;\n    uint64_t r_a64_x8 = 0;\n    uint64_t r_a64_tmp = 0;\n    r_a64_x8 = (r_a64_x3) & 0xffffffffULL;\n    r_a64_x8 = (int64_t)(int32_t)(r_rax) > (int64_t)(int32_t)(r_a64_x1) ? (r_a64_x2) & 0xffffffffULL : r_a64_x8;\n    r_a64_tmp = (r_a64_x8) & 0xffffffffULL;\n    r_a64_tmp = (r_a64_tmp + (r_a64_x4)) & 0xffffffffULL;\n    r_rax = (r_a64_tmp) & 0xffffffffULL;\n    return (r_rax) & 0xffffffffULL;\n}\n";
    assert_eq!(recovered.source, expected);
}

#[test]
fn aarch64_flag_dest_cset_snapshots_the_condition_before_the_clobber() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0xe0, 0x17, 0x9f, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("flag-dest cset");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t sel_cc_0 = 0;\n    sel_cc_0 = (int64_t)(int32_t)(r_rax) == (int64_t)(int32_t)(r_a64_x1);\n    r_rax = ((uint64_t)(int64_t)0LL) & 0xffffffffULL;\n    r_rax = sel_cc_0 != 0 ? ((uint64_t)(int64_t)1LL) & 0xffffffffULL : r_rax;\n    return (r_rax) & 0xffffffffULL;\n}\n";
    assert_eq!(r.source, expected);
}

#[test]
fn aarch64_flag_dest_three_register_csel_snapshots_the_condition() {
    let bytes: [u8; 12] = [
        0x1f, 0x00, 0x01, 0x6b, 0x40, 0xc0, 0x83, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("flag-dest csel");
    let expected: &str = "#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n    uint64_t r_rax = a0;\n    uint64_t r_a64_x1 = a1;\n    uint64_t r_a64_x2 = a2;\n    uint64_t r_a64_x3 = a3;\n    uint64_t sel_cc_0 = 0;\n    sel_cc_0 = (int64_t)(int32_t)(r_rax) > (int64_t)(int32_t)(r_a64_x1);\n    r_rax = (r_a64_x3) & 0xffffffffULL;\n    r_rax = sel_cc_0 != 0 ? (r_a64_x2) & 0xffffffffULL : r_rax;\n    return (r_rax) & 0xffffffffULL;\n}\n";
    assert_eq!(r.source, expected);
}

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
