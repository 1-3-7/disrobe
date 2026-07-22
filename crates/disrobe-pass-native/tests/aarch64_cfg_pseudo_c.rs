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
