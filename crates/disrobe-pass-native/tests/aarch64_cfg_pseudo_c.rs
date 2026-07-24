#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{Error, LeafRecovery, recover_aarch64_function};

#[test]
fn aarch64_real_clang_vector_signed_lane_max_recovers_as_a_per_lane_conditional() {
    let bytes: [u8; 8] = [0x00, 0x64, 0xa1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("smax v0.4s,v0.4s,v1.4s");
    assert!(
        r.source.contains("v0[0] > v1[0] ? v0[0] : v1[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_vector_unsigned_lane_min_recovers_as_a_per_lane_conditional() {
    let bytes: [u8; 8] = [0x00, 0x6c, 0xa1, 0x6e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("umin v0.4s,v0.4s,v1.4s");
    assert!(
        r.source.contains("(uint32_t)v0[0] < (uint32_t)v1[0]")
            || r.source.contains("v0[0] < v1[0] ? v0[0] : v1[0]"),
        "{}",
        r.source
    );
}

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
fn aarch64_real_clang_addv_reduces_four_lanes_and_fmov_returns_the_sum() {
    let bytes: [u8; 12] = [
        0x00, 0xb8, 0xb1, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("addv + fmov");
    assert!(
        r.source
            .contains("(uint32_t)v0[0] + (uint32_t)v0[1] + (uint32_t)v0[2] + (uint32_t)v0[3]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(uint32_t)((recovered_i32x4)v0)[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_smaxv_folds_a_signed_horizontal_max() {
    let bytes: [u8; 12] = [
        0x00, 0xa8, 0xb0, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("smaxv");
    assert!(
        r.source.contains("int32_t reduce_acc = v0[0]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("v0[1] > reduce_acc ? v0[1] : reduce_acc"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_sminv_folds_a_signed_horizontal_min() {
    let bytes: [u8; 12] = [
        0x00, 0xa8, 0xb1, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("sminv");
    assert!(
        r.source.contains("v0[1] < reduce_acc ? v0[1] : reduce_acc"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_umaxv_folds_an_unsigned_horizontal_max() {
    let bytes: [u8; 12] = [
        0x00, 0xa8, 0xb0, 0x6e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("umaxv");
    assert!(
        r.source.contains("uint32_t reduce_acc = (uint32_t)v0[0]"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("(uint32_t)v0[1] > reduce_acc ? (uint32_t)v0[1] : reduce_acc"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_uminv_folds_an_unsigned_horizontal_min() {
    let bytes: [u8; 12] = [
        0x00, 0xa8, 0xb1, 0x6e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("uminv");
    assert!(
        r.source
            .contains("(uint32_t)v0[1] < reduce_acc ? (uint32_t)v0[1] : reduce_acc"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_saddlv_widens_eight_signed_halfwords_into_the_sum() {
    let bytes: [u8; 12] = [
        0x00, 0x38, 0x70, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("saddlv");
    assert!(
        r.source.contains("(recovered_i16x8)(recovered_i32x4){"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("(uint32_t)(int32_t)v0[0] + (uint32_t)(int32_t)v0[1]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(uint32_t)(int32_t)v0[7]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_uaddlv_widens_eight_unsigned_halfwords_into_the_sum() {
    let bytes: [u8; 12] = [
        0x00, 0x38, 0x70, 0x6e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("uaddlv");
    assert!(
        r.source
            .contains("(uint32_t)(uint16_t)v0[0] + (uint32_t)(uint16_t)v0[1]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(uint32_t)(uint16_t)v0[7]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_addp_2d_sums_two_doublewords_and_fmov_x_returns_it() {
    let bytes: [u8; 12] = [
        0x00, 0xb8, 0xf1, 0x5e, 0x00, 0x00, 0x66, 0x9e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("addp 2d + fmov x0,d0");
    assert!(
        r.source
            .contains("(recovered_i64x2){(int64_t)((uint64_t)v0[0] + (uint64_t)v0[1]), 0}"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(uint64_t)((recovered_i64x2)v0)[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_fmov_extracts_the_low_lane_into_a_general_register() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("fmov w0,s0 alone");
    assert!(r.source.contains("recovered_i32x4 a0"), "{}", r.source);
    assert!(
        r.source.contains("(uint32_t)((recovered_i32x4)v0)[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_ldp_loads_a_vector_register_pair_from_adjacent_offsets() {
    let bytes: [u8; 12] = [
        0x00, 0x04, 0x40, 0xad, 0x20, 0x84, 0xe0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldp q0,q1 + add");
    assert!(
        r.source.contains("v0 = *(recovered_i64x2*)(r_rax)"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("v1 = *(recovered_i64x2*)(r_rax + (uint64_t)(int64_t)16LL)"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v0 = v1 + v0"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_autovectorized_sum4_recovers_load_reduce_return() {
    let bytes: [u8; 16] = [
        0x00, 0x00, 0xc0, 0x3d, 0x00, 0xb8, 0xb1, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("sum4 ldr q + addv + fmov");
    assert!(
        r.source.contains("v0 = *(recovered_i32x4*)(r_rax)"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("(uint32_t)v0[0] + (uint32_t)v0[1] + (uint32_t)v0[2] + (uint32_t)v0[3]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(uint32_t)((recovered_i32x4)v0)[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_autovectorized_dot4_recovers_two_loads_mul_reduce() {
    let bytes: [u8; 24] = [
        0x00, 0x00, 0xc0, 0x3d, 0x21, 0x00, 0xc0, 0x3d, 0x20, 0x9c, 0xa0, 0x4e, 0x00, 0xb8, 0xb1,
        0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("dot4");
    assert!(
        r.source.contains("v0 = *(recovered_i32x4*)(r_rax)"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("v1 = *(recovered_i32x4*)(r_a64_x1)"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v0 = v1 * v0"), "{}", r.source);
    assert!(
        r.source
            .contains("(uint32_t)v0[0] + (uint32_t)v0[1] + (uint32_t)v0[2] + (uint32_t)v0[3]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_autovectorized_sumall_recovers_dispatch_vectorloop_reduction_and_tail() {
    let bytes: [u8; 140] = [
        0x3f, 0x04, 0x00, 0x71, 0xeb, 0x00, 0x00, 0x54, 0x3f, 0x10, 0x00, 0x71, 0xe9, 0x03, 0x01,
        0x2a, 0xe2, 0x00, 0x00, 0x54, 0xea, 0x03, 0x1f, 0xaa, 0xe8, 0x03, 0x1f, 0xaa, 0x14, 0x00,
        0x00, 0x14, 0xe8, 0x03, 0x1f, 0xaa, 0xe0, 0x03, 0x08, 0xaa, 0xc0, 0x03, 0x5f, 0xd6, 0x00,
        0xe4, 0x00, 0x6f, 0x01, 0xe4, 0x00, 0x6f, 0x2a, 0x71, 0x7e, 0x92, 0x08, 0x40, 0x00, 0x91,
        0xeb, 0x03, 0x0a, 0xaa, 0x02, 0x8d, 0x7f, 0xad, 0x6b, 0x11, 0x00, 0xf1, 0x08, 0x81, 0x00,
        0x91, 0x40, 0x84, 0xe0, 0x4e, 0x61, 0x84, 0xe1, 0x4e, 0x61, 0xff, 0xff, 0x54, 0x20, 0x84,
        0xe0, 0x4e, 0x5f, 0x01, 0x09, 0xeb, 0x00, 0xb8, 0xf1, 0x5e, 0x08, 0x00, 0x66, 0x9e, 0xe0,
        0x00, 0x00, 0x54, 0x0b, 0x0c, 0x0a, 0x8b, 0x29, 0x01, 0x0a, 0xcb, 0x6a, 0x85, 0x40, 0xf8,
        0x29, 0x05, 0x00, 0xf1, 0x48, 0x01, 0x08, 0x8b, 0xa1, 0xff, 0xff, 0x54, 0xe0, 0x03, 0x08,
        0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("autovectorized sumall");
    assert!(!r.source.contains("goto"), "{}", r.source);
    assert!(
        r.source
            .contains("v2 = *(recovered_i64x2*)(r_a64_x8 + (uint64_t)(int64_t)-16LL)"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v0 = v2 + v0"), "{}", r.source);
    assert!(
        r.source
            .contains("(recovered_i64x2){(int64_t)((uint64_t)v0[0] + (uint64_t)v0[1]), 0}"),
        "{}",
        r.source
    );
    assert_eq!(r.source.matches("while (1)").count(), 2, "{}", r.source);
}

#[test]
fn aarch64_real_clang_gp_pair_ldp_loads_two_doublewords_and_adds_them() {
    let bytes: [u8; 12] = [
        0x08, 0x24, 0x40, 0xa9, 0x20, 0x01, 0x08, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("gp ldp x8,x9 + add");
    assert!(
        r.source.contains("*(uint64_t*)(uintptr_t)(r_rax)"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("*(uint64_t*)(uintptr_t)(r_rax + (uint64_t)(int64_t)8LL)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_signed_widening_byte_sum_versions_the_register_through_i8_i16_i32() {
    let bytes: [u8; 32] = [
        0x01, 0xa4, 0x08, 0x4f, 0x00, 0xa4, 0x08, 0x0f, 0x02, 0x00, 0x61, 0x4e, 0x00, 0x00, 0x61,
        0x0e, 0x00, 0x84, 0xa2, 0x4e, 0x00, 0xb8, 0xb1, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("signed widening byte sum");
    assert!(r.source.contains("recovered_i8x16 a0"), "{}", r.source);
    assert!(
        r.source
            .contains("vw0 = (recovered_i16x8){(int16_t)((recovered_i8x16)v0)[0]"),
        "{}",
        r.source
    );
    assert!(
        r.source.contains("(int16_t)((recovered_i8x16)v0)[8]"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("vw1 = (recovered_i32x4){(int32_t)((recovered_i16x8)vw0)[0]"),
        "{}",
        r.source
    );
    assert!(!r.source.contains("goto"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_unsigned_widening_byte_sum_zero_extends_each_lane() {
    let bytes: [u8; 32] = [
        0x01, 0xa4, 0x08, 0x6f, 0x00, 0xa4, 0x08, 0x2f, 0x02, 0x00, 0x61, 0x6e, 0x00, 0x00, 0x61,
        0x2e, 0x00, 0x84, 0xa2, 0x4e, 0x00, 0xb8, 0xb1, 0x4e, 0x00, 0x00, 0x26, 0x1e, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("unsigned widening byte sum");
    assert!(
        r.source
            .contains("(int16_t)(uint8_t)((recovered_i8x16)v0)[0]"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("(int32_t)(uint16_t)((recovered_i16x8)vw0)[0]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_widening_that_returns_the_vector_abstains_rather_than_misemitting() {
    let vmovl: [u8; 8] = [0x00, 0xa4, 0x08, 0x0f, 0xc0, 0x03, 0x5f, 0xd6];
    let error: Error = recover_aarch64_function(&vmovl, 0).expect_err("vmovl must abstain");
    assert!(
        format!("{error:?}").contains("widening-long chain without a scalar result"),
        "{error:?}"
    );
}

#[test]
fn aarch64_widening_across_control_flow_abstains_rather_than_misversioning() {
    let branchy: [u8; 12] = [
        0x40, 0x00, 0x00, 0x34, 0x00, 0xa4, 0x08, 0x0f, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error: Error = recover_aarch64_function(&branchy, 0).expect_err("branchy widen abstains");
    assert!(
        format!("{error:?}").contains("widening-long register versioning across control flow"),
        "{error:?}"
    );
}

#[test]
fn aarch64_real_clang_stp_stores_a_vector_register_pair_to_adjacent_offsets() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0xad, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("stp q0,q0");
    assert!(
        r.source.contains("*(recovered_i8x16*)(r_rax) = v0"),
        "{}",
        r.source
    );
    assert!(
        r.source
            .contains("*(recovered_i8x16*)(r_rax + (uint64_t)(int64_t)16LL) = v0"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_scaled_register_index_load_recovers_as_array_access() {
    let bytes: [u8; 8] = [0x00, 0x78, 0x61, 0xb8, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldr w0,[x0,x1,lsl #2]");
    assert!(
        r.source
            .contains("*(uint32_t*)(uintptr_t)(r_rax + r_a64_x1 * 4ULL)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_sign_extended_word_index_load_recovers_with_signed_widening() {
    let bytes: [u8; 8] = [0x00, 0xd8, 0x61, 0xb8, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldr w0,[x0,w1,sxtw #2]");
    assert!(
        r.source
            .contains("(uint64_t)(int64_t)(int32_t)(uint32_t)r_a64_x1 * 4ULL"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_zero_extended_word_index_load_recovers_with_unsigned_widening() {
    let bytes: [u8; 8] = [0x00, 0x58, 0x61, 0xb8, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldr w0,[x0,w1,uxtw #2]");
    assert!(
        r.source.contains("(uint64_t)(uint32_t)r_a64_x1 * 4ULL"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_extended_word_index_never_recovers_as_a_raw_register_array_subscript() {
    let bytes: [u8; 16] = [
        0x08, 0xd8, 0x61, 0xb8, 0x09, 0xd8, 0x62, 0xb8, 0x20, 0x01, 0x08, 0x0b, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("arr[i] + arr[j], int index");
    assert!(
        r.source.contains("(int32_t)(uint32_t)r_a64_x1")
            && r.source.contains("(int32_t)(uint32_t)r_a64_x2"),
        "{}",
        r.source
    );
    assert!(
        !r.source.contains("[r_a64_x1]") && !r.source.contains("[r_a64_x2]"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_unscaled_sign_extended_word_index_byte_load_recovers() {
    let bytes: [u8; 8] = [0x00, 0xc8, 0x61, 0x38, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrb w0,[x0,w1,sxtw]");
    assert!(
        r.source
            .contains("(uint64_t)(int64_t)(int32_t)(uint32_t)r_a64_x1"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_post_index_byte_load_lifts_the_access_before_the_base_update() {
    let bytes: [u8; 8] = [0x29, 0x14, 0x40, 0x38, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ldrb w9,[x1],#1");
    let load_at: usize = r.source.find("uint8_t").expect(&r.source);
    let update_at: usize = r
        .source
        .rfind("r_a64_x1 = r_a64_x1 +")
        .or_else(|| r.source.rfind("r_a64_x1 +"))
        .expect(&r.source);
    assert!(load_at < update_at, "{}", r.source);
}

#[test]
fn aarch64_real_clang_post_index_byte_store_lifts_the_store_before_the_base_update() {
    let bytes: [u8; 8] = [0x09, 0x14, 0x00, 0x38, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("strb w9,[x0],#1");
    let store_at: usize = r.source.find("uint8_t").expect(&r.source);
    let update_at: usize = r.source.rfind("r_rax = r_rax +").expect(&r.source);
    assert!(store_at < update_at, "{}", r.source);
}

#[test]
fn aarch64_real_clang_ubfiz_recovers_as_a_masked_left_shift() {
    let bytes: [u8; 8] = [0x00, 0x7c, 0x7e, 0xd3, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ubfiz x0,x0,#2,#32");
    assert!(r.source.contains("4294967295"), "{}", r.source);
    assert!(r.source.contains("<< ((("), "{}", r.source);
    let mask_at: usize = r.source.find("4294967295").expect(&r.source);
    let shift_at: usize = r.source.find("<< (((").expect(&r.source);
    assert!(mask_at < shift_at, "{}", r.source);
}

#[test]
fn aarch64_real_clang_ubfx_recovers_as_a_right_shift_then_mask() {
    let bytes: [u8; 8] = [0x00, 0x2c, 0x04, 0x53, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("ubfx w0,w0,#4,#8");
    let shift_at: usize = r.source.find(">> (((").expect(&r.source);
    let mask_at: usize = r.source.find("255").expect(&r.source);
    assert!(shift_at < mask_at, "{}", r.source);
}

#[test]
fn aarch64_real_clang_large_bitmask_immediate_recovers_as_a_reinterpreted_mask() {
    let bytes: [u8; 8] = [0x00, 0xf0, 0x7d, 0x92, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("and x0,x0,#-8 mask");
    assert!(
        r.source.contains("& ((uint64_t)(int64_t)-8LL)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_umull_recovers_as_unsigned_widening_multiply() {
    let bytes: [u8; 8] = [0x20, 0x7c, 0xa0, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("umull x0,w1,w0");
    assert!(
        r.source
            .contains("(uint64_t)(uint32_t)r_a64_tmp * (uint64_t)(uint32_t)(r_rax)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_smull_recovers_as_signed_widening_multiply() {
    let bytes: [u8; 8] = [0x20, 0x7c, 0x20, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("smull x0,w1,w0");
    assert!(
        r.source
            .contains("(int64_t)(int32_t)r_a64_tmp * (int64_t)(int32_t)(r_rax)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_sdiv_recovers_as_signed_division() {
    let bytes: [u8; 8] = [0x00, 0x0c, 0xc1, 0x1a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("sdiv w0,w0,w1");
    assert!(
        r.source
            .contains("(int32_t)r_a64_tmp / (int32_t)(r_a64_x1)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_udiv_recovers_as_unsigned_division() {
    let bytes: [u8; 8] = [0x00, 0x08, 0xc1, 0x1a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("udiv w0,w0,w1");
    assert!(
        r.source
            .contains("(uint32_t)r_a64_tmp / (uint32_t)(r_a64_x1)"),
        "{}",
        r.source
    );
}

#[test]
fn aarch64_real_clang_sdiv64_recovers_as_signed_doubleword_division() {
    let bytes: [u8; 8] = [0x00, 0x0c, 0xc1, 0x9a, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("sdiv x0,x0,x1");
    assert!(
        r.source
            .contains("(int64_t)r_a64_tmp / (int64_t)(r_a64_x1)"),
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
fn aarch64_real_clang_vector_bic_recovers_as_elementwise_and_not() {
    let bytes: [u8; 8] = [0x00, 0x1c, 0x61, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("vector bic");
    assert!(r.source.contains("v0 = v0 & ~v1"), "{}", r.source);
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
fn loop_with_distinct_mid_body_exit_targets_keeps_one_break_and_one_return() {
    let bytes: [u8; 36] = [
        0x1f, 0x00, 0x01, 0xeb, 0xea, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x1f, 0x00, 0x02,
        0xeb, 0x60, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0xc0, 0x03,
        0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("two distinct loop exits recover");

    let (body, tail): (String, String) = split_around_loop(&recovered.source);
    assert!(
        body.contains("if ((int64_t)(int64_t)(r_rax) < (int64_t)(int64_t)(r_a64_x1)) {"),
        "{}",
        recovered.source
    );
    assert!(
        body.contains("if ((int64_t)(int64_t)(r_rax) != (int64_t)(int64_t)(r_a64_x2)) {"),
        "{}",
        recovered.source
    );
    assert!(body.contains("return r_rax;"), "{}", recovered.source);
    assert!(body.contains("break;"), "{}", recovered.source);
    assert!(body.contains("continue;"), "{}", recovered.source);
    assert_eq!(
        body.matches("r_a64_tmp = r_a64_tmp + ((uint64_t)(int64_t)1LL);")
            .count(),
        2,
        "{}",
        recovered.source
    );
    assert!(tail.contains("return r_rax;"), "{}", recovered.source);
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
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

#[test]
fn real_clang_o1_popcount_loop_snapshots_the_condition_before_the_latch_copy() {
    let bytes: [u8; 40] = [
        0x20, 0x01, 0x00, 0x34, 0xe8, 0x03, 0x00, 0x2a, 0xe0, 0x03, 0x1f, 0x2a, 0x09, 0x7d, 0x01,
        0x53, 0x0a, 0x01, 0x00, 0x12, 0x1f, 0x05, 0x00, 0x71, 0x00, 0x00, 0x0a, 0x0b, 0xe8, 0x03,
        0x09, 0x2a, 0x68, 0xff, 0xff, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("clobbered loop condition recovers");

    let snapshot: Option<usize> = recovered
        .source
        .find("sel_cc_0 = (uint64_t)((r_a64_x8) & 0xffffffffULL) > ");
    let latch_copy: Option<usize> = recovered.source.find("r_a64_x8 = (r_a64_x9)");
    let (snapshot, latch_copy): (usize, usize) = (
        snapshot.unwrap_or_else(|| panic!("{}", recovered.source)),
        latch_copy.unwrap_or_else(|| panic!("{}", recovered.source)),
    );
    assert!(snapshot < latch_copy, "{}", recovered.source);
    assert!(
        recovered.source.contains("} while (sel_cc_0 != 0);"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    assert!(recovered.lifted_loop, "{}", recovered.source);
}

#[test]
fn clang_assembler_unclobbered_compare_keeps_the_direct_predicate() {
    let bytes: [u8; 28] = [
        0x1f, 0x00, 0x01, 0xeb, 0xe3, 0x03, 0x02, 0xaa, 0x6c, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80,
        0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("unclobbered compare recovers");

    assert!(
        recovered
            .source
            .contains("if ((int64_t)(int64_t)(r_rax) <= (int64_t)(int64_t)(r_a64_x1)) {"),
        "{}",
        recovered.source
    );
    assert!(!recovered.source.contains("sel_cc"), "{}", recovered.source);
}

#[test]
fn clobbered_compare_with_two_conditional_consumers_still_rejects() {
    let bytes: [u8; 40] = [
        0x1f, 0x00, 0x01, 0xeb, 0xe0, 0x03, 0x02, 0xaa, 0x8c, 0x00, 0x00, 0x54, 0xab, 0x00, 0x00,
        0x54, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03,
        0x5f, 0xd6, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];

    let result: Result<LeafRecovery, Error> = recover_aarch64_function(&bytes, 0);
    let error: Error = result.expect_err("two consumers of a clobbered compare must reject");
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

fn split_around_loop(source: &str) -> (String, String) {
    let start: usize = source.find("    while (1) {").expect("a recovered loop");
    let end: usize = source[start..]
        .find("\n    }\n")
        .map(|offset: usize| start + offset)
        .expect("a closing brace for the recovered loop");
    (source[start..end].to_owned(), source[end..].to_owned())
}

#[test]
fn aarch64_real_clang_early_return_inside_a_loop_stays_a_return() {
    let bytes: [u8; 52] = [
        0x3f, 0x04, 0x00, 0x71, 0x4b, 0x01, 0x00, 0x54, 0xe8, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x1f,
        0xaa, 0xe9, 0x03, 0x01, 0x2a, 0x0a, 0x79, 0x60, 0xb8, 0x5f, 0x01, 0x02, 0x6b, 0xa0, 0x00,
        0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x3f, 0x01, 0x00, 0xeb, 0x61, 0xff, 0xff, 0x54, 0x00,
        0x00, 0x80, 0x12, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("a linear search with an early return recovers");
    let (body, tail): (String, String) = split_around_loop(&recovered.source);
    assert!(
        body.contains("return (r_rax) & 0xffffffffULL;"),
        "the match arm must return from inside the loop: {}",
        recovered.source
    );
    assert!(body.contains("break;"), "{}", recovered.source);
    assert!(body.contains("continue;"), "{}", recovered.source);
    assert!(
        !body.contains("4294967295LL"),
        "the not-found value must not be produced inside the loop: {}",
        recovered.source
    );
    assert!(
        tail.contains("4294967295LL"),
        "the not-found value must be returned after the loop: {}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
    let rust_source: String = recovered.rust_source.expect("a rust rendering");
    assert!(rust_source.contains("loop {"), "{rust_source}");
    assert!(rust_source.contains("return r_rax"), "{rust_source}");
}

#[test]
fn aarch64_real_clang_tail_merged_epilogue_returns_a_value_per_path() {
    let bytes: [u8; 40] = [
        0x3f, 0x04, 0x00, 0x71, 0xcb, 0x00, 0x00, 0x54, 0xe9, 0x03, 0x01, 0x2a, 0x08, 0x44, 0x40,
        0xb8, 0x88, 0x00, 0xf8, 0x37, 0x29, 0x05, 0x00, 0xf1, 0xa1, 0xff, 0xff, 0x54, 0xe8, 0x03,
        0x1f, 0x2a, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0)
        .expect("a scan returning the first negative element recovers");
    let (body, tail): (String, String) = split_around_loop(&recovered.source);
    assert!(
        body.contains("r_rax = (r_a64_x8) & 0xffffffffULL;")
            && body.contains("return (r_rax) & 0xffffffffULL;"),
        "the negative element must be returned from inside the loop: {}",
        recovered.source
    );
    assert!(
        tail.contains("r_a64_x8 = ((uint64_t)(int64_t)0LL) & 0xffffffffULL;"),
        "the zero result must be produced after the loop: {}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn aarch64_real_clang_unoptimized_early_return_loop_recovers() {
    let bytes: [u8; 128] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0b, 0x00, 0xf9, 0xe1, 0x0f, 0x00, 0xb9, 0xe2, 0x0b, 0x00,
        0xb9, 0xff, 0x07, 0x00, 0xb9, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x07, 0x40, 0xb9, 0xe9, 0x0f,
        0x40, 0xb9, 0x08, 0x01, 0x09, 0x6b, 0x2a, 0x02, 0x00, 0x54, 0x01, 0x00, 0x00, 0x14, 0xe8,
        0x0b, 0x40, 0xf9, 0xe9, 0x07, 0x80, 0xb9, 0x08, 0x79, 0x69, 0xb8, 0xe9, 0x0b, 0x40, 0xb9,
        0x08, 0x01, 0x09, 0x6b, 0xa1, 0x00, 0x00, 0x54, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x07, 0x40,
        0xb9, 0xe8, 0x1f, 0x00, 0xb9, 0x09, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x07,
        0x40, 0xb9, 0x08, 0x05, 0x00, 0x11, 0xe8, 0x07, 0x00, 0xb9, 0xed, 0xff, 0xff, 0x17, 0x08,
        0x00, 0x80, 0x12, 0xe8, 0x1f, 0x00, 0xb9, 0x01, 0x00, 0x00, 0x14, 0xe0, 0x1f, 0x40, 0xb9,
        0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0)
        .expect("an unoptimized linear search with an early return recovers");
    let (body, tail): (String, String) = split_around_loop(&recovered.source);
    assert!(
        body.contains("return (r_rax) & 0xffffffffULL;"),
        "the match arm must return from inside the loop: {}",
        recovered.source
    );
    assert!(body.contains("break;"), "{}", recovered.source);
    assert!(
        !body.contains("4294967295LL"),
        "the not-found value must not be produced inside the loop: {}",
        recovered.source
    );
    assert!(
        tail.contains("4294967295LL"),
        "the not-found value must be returned after the loop: {}",
        recovered.source
    );
    assert!(!recovered.source.contains("goto"), "{}", recovered.source);
}

#[test]
fn aarch64_real_clang_bitwise_and_arithmetic_share_one_lane_typed_vector_register() {
    let bytes: [u8; 160] = [
        0x3f, 0x04, 0x00, 0x71, 0xeb, 0x00, 0x00, 0x54, 0x3f, 0x20, 0x00, 0x71, 0xe9, 0x03, 0x01,
        0x2a, 0xe2, 0x00, 0x00, 0x54, 0xea, 0x03, 0x1f, 0xaa, 0xe8, 0x03, 0x1f, 0x2a, 0x17, 0x00,
        0x00, 0x14, 0xe8, 0x03, 0x1f, 0x2a, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6, 0x00,
        0xe4, 0x00, 0x6f, 0x21, 0x04, 0x00, 0x4f, 0x2a, 0x6d, 0x7d, 0x92, 0x02, 0xe4, 0x00, 0x6f,
        0x08, 0x40, 0x00, 0x91, 0x2b, 0x6d, 0x7d, 0x92, 0x03, 0x91, 0x7f, 0xad, 0x6b, 0x21, 0x00,
        0xf1, 0x08, 0x81, 0x00, 0x91, 0x23, 0x1c, 0x63, 0x4e, 0x24, 0x1c, 0x64, 0x4e, 0x60, 0x84,
        0xa0, 0x4e, 0x82, 0x84, 0xa2, 0x4e, 0x21, 0xff, 0xff, 0x54, 0x40, 0x84, 0xa0, 0x4e, 0x5f,
        0x01, 0x09, 0xeb, 0x00, 0xb8, 0xb1, 0x4e, 0x08, 0x00, 0x26, 0x1e, 0x20, 0x01, 0x00, 0x54,
        0x0b, 0x08, 0x0a, 0x8b, 0x29, 0x01, 0x0a, 0xcb, 0x2a, 0x00, 0x80, 0x52, 0x6c, 0x45, 0x40,
        0xb8, 0x29, 0x05, 0x00, 0xf1, 0x4c, 0x01, 0x2c, 0x0a, 0x88, 0x01, 0x08, 0x0b, 0x81, 0xff,
        0xff, 0x54, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("bic and .4s add over one register recovers");
    assert!(
        r.source
            .contains("typedef int32_t recovered_i32x4 __attribute__((vector_size(16)));"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v3 = v1 & ~v3;"), "{}", r.source);
    assert!(
        r.source
            .contains("v0 = (recovered_i32x4){(int32_t)0, (int32_t)0, (int32_t)0, (int32_t)0};"),
        "{}",
        r.source
    );
    assert!(!r.source.contains("recovered_i64x2"), "{}", r.source);
    assert!(!r.source.contains("recovered_i8x16"), "{}", r.source);
}

#[test]
fn aarch64_real_clang_zero_accumulator_movi_shares_a_lane_typed_register() {
    let bytes: [u8; 140] = [
        0x3f, 0x04, 0x00, 0x71, 0xeb, 0x00, 0x00, 0x54, 0x3f, 0x20, 0x00, 0x71, 0xe9, 0x03, 0x01,
        0x2a, 0xe2, 0x00, 0x00, 0x54, 0xea, 0x03, 0x1f, 0xaa, 0xe8, 0x03, 0x1f, 0x2a, 0x14, 0x00,
        0x00, 0x14, 0xe8, 0x03, 0x1f, 0x2a, 0xe0, 0x03, 0x08, 0x2a, 0xc0, 0x03, 0x5f, 0xd6, 0x00,
        0xe4, 0x00, 0x6f, 0x01, 0xe4, 0x00, 0x6f, 0x2a, 0x6d, 0x7d, 0x92, 0x08, 0x40, 0x00, 0x91,
        0x2b, 0x6d, 0x7d, 0x92, 0x02, 0x8d, 0x7f, 0xad, 0x6b, 0x21, 0x00, 0xf1, 0x08, 0x81, 0x00,
        0x91, 0x40, 0x84, 0xa0, 0x4e, 0x61, 0x84, 0xa1, 0x4e, 0x61, 0xff, 0xff, 0x54, 0x20, 0x84,
        0xa0, 0x4e, 0x5f, 0x01, 0x09, 0xeb, 0x00, 0xb8, 0xb1, 0x4e, 0x08, 0x00, 0x26, 0x1e, 0xe0,
        0x00, 0x00, 0x54, 0x0b, 0x08, 0x0a, 0x8b, 0x29, 0x01, 0x0a, 0xcb, 0x6a, 0x45, 0x40, 0xb8,
        0x29, 0x05, 0x00, 0xf1, 0x48, 0x01, 0x08, 0x0b, 0xa1, 0xff, 0xff, 0x54, 0xe0, 0x03, 0x08,
        0x2a, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let r: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("zero-accumulator .4s reduction recovers");
    assert!(
        r.source
            .contains("v0 = (recovered_i32x4){(int32_t)0, (int32_t)0, (int32_t)0, (int32_t)0};"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v0 = v2 + v0;"), "{}", r.source);
    assert!(!r.source.contains("recovered_i64x2"), "{}", r.source);
}

#[test]
fn aarch64_full_register_mov_recovers_as_a_lane_typed_copy() {
    let bytes: [u8; 16] = [
        0x40, 0x04, 0x00, 0x4f, 0x01, 0x1c, 0xa0, 0x4e, 0x00, 0x84, 0xa1, 0x4e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let r: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("mov vd.16b, vn.16b recovers as a copy");
    assert!(
        r.source.contains("recovered_i32x4 recovered(void)"),
        "{}",
        r.source
    );
    assert!(r.source.contains("v1 = v0 | v0;"), "{}", r.source);
    assert!(r.source.contains("v0 = v0 + v1;"), "{}", r.source);
    assert!(!r.source.contains("recovered_i8x16"), "{}", r.source);
}
