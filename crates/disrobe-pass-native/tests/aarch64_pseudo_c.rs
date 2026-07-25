#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, PseudoReg, ResolvedCall, recover_aarch64_function,
    recover_aarch64_function_with_calls, recover_leaf_function_abi,
    recover_leaf_function_in_object,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};

fn find_program(name: &str) -> Option<PathBuf> {
    let path: OsString = std::env::var_os("PATH")?;
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_owned()]
    } else {
        vec![name.to_owned()]
    };
    std::env::split_paths(&path)
        .flat_map(|directory: PathBuf| names.iter().map(move |name: &String| directory.join(name)))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn run_tool(program: &Path, args: Vec<OsString>) -> CapturedOutput {
    let output: CapturedOutput = run_captured(program, &args, Duration::from_secs(30), 1 << 20)
        .expect("spawn aarch64 ground-truth tool")
        .expect("aarch64 ground-truth tool timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn clang_o2_integer_add_lifts_through_shared_ir() {
    let bytes: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 add");
    assert_eq!(
        recovered.params,
        vec![PseudoReg::Rax, PseudoReg::A64X1, PseudoReg::A64X2]
    );
    assert!(recovered.source.contains("r_rax = r_a64_tmp"));
    assert!(recovered.source.contains("r_a64_x1"));
    assert!(recovered.source.contains("r_a64_x2"));
    assert!(recovered.rust_source.is_some());
}

#[test]
fn clang_o2_shifted_integer_alu_lifts() {
    let bytes: [u8; 28] = [
        0x48, 0xfc, 0x43, 0x93, 0x29, 0x00, 0x00, 0x8a, 0x4a, 0x00, 0x01, 0xca, 0x49, 0x01, 0x09,
        0xaa, 0x08, 0x09, 0x80, 0x8b, 0x00, 0x0d, 0x09, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 alu");
    assert_eq!(recovered.params.len(), 3);
    assert!(recovered.source.contains(" & "));
    assert!(recovered.source.contains(" | "));
    assert!(recovered.source.contains(" ^ "));
    assert!(recovered.source.contains(" >> "), "{}", recovered.source);
    assert!(recovered.source.contains(" << "), "{}", recovered.source);
}

#[test]
fn clang_o2_madd_and_msub_lift() {
    let madd: [u8; 8] = [0x20, 0x08, 0x00, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let msub: [u8; 8] = [0x20, 0x88, 0x00, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    let added: LeafRecovery = recover_aarch64_function(&madd, 0).expect("aarch64 madd");
    let subtracted: LeafRecovery = recover_aarch64_function(&msub, 0).expect("aarch64 msub");
    assert!(added.source.contains(" * ") && added.source.contains(" + "));
    assert!(subtracted.source.contains(" * ") && subtracted.source.contains(" - "));
    assert_eq!(added.params.len(), 3);
    assert_eq!(subtracted.params.len(), 3);
}

#[test]
fn clang_mov_wide_constant_materialization_lifts() {
    let wide: [u8; 20] = [
        0x00, 0xde, 0x9b, 0xd2, 0x80, 0x57, 0xb3, 0xf2, 0x00, 0xcf, 0xca, 0xf2, 0x80, 0x46, 0xe2,
        0xf2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let inverted: [u8; 8] = [0x80, 0x46, 0x82, 0x92, 0xc0, 0x03, 0x5f, 0xd6];
    let zero: [u8; 8] = [0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&wide, 0).expect("mov wide");
    let recovered_inverted: LeafRecovery =
        recover_aarch64_function(&inverted, 0).expect("mov inverted");
    let recovered_zero: LeafRecovery = recover_aarch64_function(&zero, 0).expect("mov zero");
    assert!(recovered.params.is_empty());
    assert!(recovered.source.contains("57072"));
    assert!(recovered.source.matches(" | ").count() >= 3);
    assert!(recovered_inverted.source.contains("4661"));
    assert!(recovered_zero.source.contains("r_rax = 0"));
}

#[test]
fn clang_o0_spill_frame_lifts_stack_slots() {
    let bytes: [u8; 44] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xf9, 0xe1, 0x0b, 0x00, 0xf9, 0xe2, 0x07, 0x00,
        0xf9, 0xe8, 0x0f, 0x40, 0xf9, 0xe9, 0x0b, 0x40, 0xf9, 0x08, 0x01, 0x09, 0x8b, 0xe9, 0x07,
        0x40, 0xf9, 0x00, 0x01, 0x09, 0x8b, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 frame");
    assert_eq!(recovered.params.len(), 3);
    assert!(recovered.source.contains("stack_frame[32]"));
    assert!(recovered.source.contains("r_rsp"));
    assert!(
        recovered
            .source
            .contains("uint64_t recovered(uint64_t a0, uint64_t a1, uint64_t a2)")
    );
}

#[test]
fn clang_o2_pair_load_and_store_lift() {
    let load_pair: [u8; 12] = [
        0x08, 0x24, 0x40, 0xa9, 0x20, 0x01, 0x08, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let store_pair: [u8; 8] = [0x01, 0x08, 0x00, 0xa9, 0xc0, 0x03, 0x5f, 0xd6];
    let loaded: LeafRecovery = recover_aarch64_function(&load_pair, 0).expect("aarch64 ldp");
    let stored: LeafRecovery = recover_aarch64_function(&store_pair, 0).expect("aarch64 stp");
    assert_eq!(loaded.params, vec![PseudoReg::Rax]);
    assert_eq!(loaded.source.matches("*(uint64_t*)").count(), 2);
    assert_eq!(stored.params.len(), 3);
    assert!(stored.source.contains("recovered_struct_0_t"));
    assert!(stored.source.contains("recovered_struct_0->field_0"));
    assert!(stored.source.contains("recovered_struct_0->field_8"));
    let rust: &str = stored.rust_source.as_deref().expect("aarch64 struct rust");
    assert!(rust.contains("struct RecoveredStruct0"));
    assert!(rust.contains("field_0"));
    assert!(rust.contains("field_8"));
}

#[test]
fn clang_o0_cbnz_diamond_structures_if_else() {
    let bytes: [u8; 60] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x03, 0x00, 0xf9, 0xe8, 0x03, 0x40, 0xf9, 0xa8, 0x00, 0x00,
        0xb5, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x00, 0x80, 0xd2, 0xe8, 0x07, 0x00, 0xf9, 0x05, 0x00,
        0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x05, 0x00, 0x91, 0xe8, 0x07, 0x00, 0xf9, 0x01,
        0x00, 0x00, 0x14, 0xe0, 0x07, 0x40, 0xf9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0x2c).expect("aarch64 cbnz diamond");
    assert_eq!(recovered.params, vec![PseudoReg::Rax]);
    assert!(recovered.source.contains("if ("));
    assert!(recovered.source.contains("else"));
    assert!(recovered.source.contains("== 0") || recovered.source.contains("!= 0"));
}

#[test]
fn clang_o0_tbnz_diamond_structures_bit_test() {
    let bytes: [u8; 64] = [
        0xff, 0x43, 0x00, 0xd1, 0xe0, 0x03, 0x00, 0xf9, 0xe8, 0x03, 0x40, 0xf9, 0xc8, 0x00, 0x28,
        0x37, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x0d, 0x00, 0x91, 0xe8, 0x07,
        0x00, 0xf9, 0x05, 0x00, 0x00, 0x14, 0xe8, 0x03, 0x40, 0xf9, 0x08, 0x11, 0x00, 0xf1, 0xe8,
        0x07, 0x00, 0xf9, 0x01, 0x00, 0x00, 0x14, 0xe0, 0x07, 0x40, 0xf9, 0xff, 0x43, 0x00, 0x91,
        0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0x68).expect("aarch64 tbnz diamond");
    assert!(recovered.source.contains("0x20"));
    assert!(recovered.source.contains("if ("));
    assert!(recovered.source.contains("else"));
}

#[test]
fn clang_o0_nzcv_loop_uses_shared_structurer() {
    let bytes: [u8; 88] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xf9, 0xff, 0x0b, 0x00, 0xf9, 0xff, 0x07, 0x00,
        0xf9, 0x01, 0x00, 0x00, 0x14, 0xe8, 0x07, 0x40, 0xf9, 0xe9, 0x0f, 0x40, 0xf9, 0x08, 0x01,
        0x09, 0xeb, 0x6a, 0x01, 0x00, 0x54, 0x01, 0x00, 0x00, 0x14, 0xe9, 0x07, 0x40, 0xf9, 0xe8,
        0x0b, 0x40, 0xf9, 0x08, 0x01, 0x09, 0x8b, 0xe8, 0x0b, 0x00, 0xf9, 0x01, 0x00, 0x00, 0x14,
        0xe8, 0x07, 0x40, 0xf9, 0x08, 0x05, 0x00, 0x91, 0xe8, 0x07, 0x00, 0xf9, 0xf3, 0xff, 0xff,
        0x17, 0xe0, 0x0b, 0x40, 0xf9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0xa8).expect("aarch64 nzcv loop");
    assert!(recovered.lifted_loop);
    assert!(recovered.source.contains("while (1)"));
    assert!(recovered.source.contains("break;"));
}

#[test]
fn clang_assembler_cmp_cmn_and_tst_drive_conditions() {
    let cmp: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xeb, 0x6d, 0x00, 0x00, 0x54, 0x00, 0x00, 0x01, 0xcb, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x01, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let cmn: [u8; 24] = [
        0x1f, 0x14, 0x00, 0xb1, 0x61, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let tst: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xea, 0x60, 0x00, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x60, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for (bytes, base) in [(&cmp[..], 0_u64), (&cmn[..], 0x18), (&tst[..], 0x30)] {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, base).expect("aarch64 flags branch");
        assert!(recovered.source.contains("if ("));
        assert!(recovered.source.matches("return ").count() >= 2);
    }
}

#[test]
fn clang_o2_direct_call_tracks_aapcs64_and_callee_saved_register() {
    let bytes: [u8; 36] = [
        0xfd, 0x7b, 0xbe, 0xa9, 0xf3, 0x0b, 0x00, 0xf9, 0xfd, 0x03, 0x00, 0x91, 0x33, 0x00, 0x00,
        0x8b, 0x00, 0x00, 0x00, 0x94, 0x60, 0x02, 0x00, 0x8b, 0xf3, 0x0b, 0x40, 0xf9, 0xfd, 0x7b,
        0xc2, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let calls: [ResolvedCall; 1] = [ResolvedCall {
        target: 0x10,
        name: Some("helper".to_owned()),
        arg_count: 1,
    }];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 direct call");
    assert_eq!(recovered.params, vec![PseudoReg::Rax, PseudoReg::A64X1]);
    assert_eq!(recovered.call_targets, vec![0x10]);
    assert!(recovered.source.contains("helper(r_rax)"));
    assert!(recovered.source.contains("r_a64_x19"));
}

#[test]
fn callee_saved_pair_writeback_lifts() {
    let bytes: [u8; 20] = [
        0xf3, 0x53, 0xbf, 0xa9, 0xf3, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x13, 0xaa, 0xf3, 0x53, 0xc1,
        0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("aarch64 callee-save pair");
    assert_eq!(recovered.params, vec![PseudoReg::Rax]);
    assert!(recovered.source.contains("r_a64_x19 = r_rax"));
}

#[test]
fn frame_pointer_omitted_link_register_frame_lifts() {
    let bytes: [u8; 16] = [
        0xfe, 0x0f, 0x1f, 0xf8, 0x00, 0x00, 0x00, 0x94, 0xfe, 0x07, 0x41, 0xf8, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let calls: [ResolvedCall; 1] = [ResolvedCall {
        target: 4,
        name: Some("helper".to_owned()),
        arg_count: 0,
    }];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 lr frame");
    assert!(recovered.params.is_empty());
    assert!(recovered.source.contains("helper()"));
    assert_eq!(recovered.call_targets, vec![4]);
}

#[test]
fn clang_o2_aapcs64_sret_uses_x8() {
    let bytes: [u8; 12] = [
        0x00, 0x05, 0x00, 0xa9, 0x02, 0x09, 0x00, 0xf9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0x84).expect("aarch64 sret");
    assert_eq!(recovered.params.len(), 3);
    assert_eq!(recovered.sret.as_ref().map(|sret| sret.size), Some(24));
    assert!(recovered.source.contains("recovered_sret_t"));
    assert!(recovered.source.contains("r_a64_x8"));
    assert!(recovered.rust_source.is_none());
}

#[test]
fn clang_o1_aapcs64_stack_arguments_lift() {
    let bytes: [u8; 20] = [
        0xe8, 0x27, 0x40, 0xa9, 0xea, 0x00, 0x00, 0x8b, 0x48, 0x01, 0x08, 0x8b, 0x00, 0x01, 0x09,
        0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("aarch64 stack args");
    assert_eq!(recovered.params.len(), 4);
    assert!(recovered.params.contains(&PseudoReg::A64Stack0));
    assert!(recovered.params.contains(&PseudoReg::A64Stack1));
    assert!(recovered.source.contains("r_a64_stack0 = a2"));
    assert!(recovered.source.contains("r_a64_stack1 = a3"));
}

#[test]
fn clang_frame_pointer_and_split_stack_arguments_lift() {
    let frame_pointer: [u8; 24] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xa8, 0x0b, 0x40, 0xf9, 0xe0, 0x03, 0x08,
        0xaa, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let split_stack: [u8; 32] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xff, 0x83, 0x00, 0xd1, 0xe8, 0x1b, 0x40,
        0xf9, 0xe0, 0x03, 0x08, 0xaa, 0xff, 0x83, 0x00, 0x91, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    for bytes in [&frame_pointer[..], &split_stack[..]] {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, 0).expect("aarch64 framed stack argument");
        assert_eq!(recovered.params, vec![PseudoReg::A64Stack0]);
        assert!(recovered.source.contains("r_a64_stack0 = a0"));
    }
}

#[test]
fn clang_o1_outgoing_stack_argument_lifts() {
    let bytes: [u8; 60] = [
        0xff, 0x83, 0x00, 0xd1, 0xfd, 0x7b, 0x01, 0xa9, 0xfd, 0x43, 0x00, 0x91, 0x28, 0x01, 0x80,
        0x52, 0x62, 0x00, 0x80, 0x52, 0x83, 0x00, 0x80, 0x52, 0xa4, 0x00, 0x80, 0x52, 0xc5, 0x00,
        0x80, 0x52, 0xe6, 0x00, 0x80, 0x52, 0x07, 0x01, 0x80, 0x52, 0xe8, 0x03, 0x00, 0xf9, 0x00,
        0x00, 0x00, 0x94, 0xfd, 0x7b, 0x41, 0xa9, 0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let calls: [ResolvedCall; 1] = [ResolvedCall {
        target: 44,
        name: Some("helper".to_owned()),
        arg_count: 9,
    }];
    let recovered: LeafRecovery =
        recover_aarch64_function_with_calls(&bytes, 0, &calls).expect("aarch64 call9");
    assert_eq!(recovered.params, vec![PseudoReg::Rax, PseudoReg::A64X1]);
    assert!(recovered.source.contains("r_a64_outgoing0 = r_a64_x8"));
    assert!(recovered.source.contains("helper("));
    assert!(recovered.source.contains("r_a64_outgoing0)"));
}

#[test]
fn clang_assembler_pre_and_post_index_writeback_lift() {
    let bytes: [u8; 24] = [
        0x01, 0x8c, 0x40, 0xf8, 0x02, 0x84, 0x00, 0xf8, 0x03, 0x10, 0xc1, 0xa9, 0x05, 0x18, 0x81,
        0xa8, 0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("aarch64 indexed memory");
    assert_eq!(recovered.params.len(), 4);
    assert!(recovered.source.matches("r_rax = r_rax +").count() >= 4);
    assert!(recovered.source.matches("*(uint64_t*)").count() >= 4);
}

#[test]
fn clang_d_register_post_index_copy_loop_lifts() {
    let bytes: [u8; 32] = [
        0x5f, 0x04, 0x00, 0x71, 0xcb, 0x00, 0x00, 0x54, 0xe8, 0x03, 0x02, 0x2a, 0x20, 0x84, 0x40,
        0xfc, 0x08, 0x05, 0x00, 0xf1, 0x00, 0x84, 0x00, 0xfc, 0xa1, 0xff, 0xff, 0x54, 0xc0, 0x03,
        0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("d-register post-index copy loop");
    assert!(
        recovered.source.contains("recovered_i8x8"),
        "{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("(__typeof__(v0)){0}"),
        "{}",
        recovered.source
    );
    assert!(
        recovered
            .source
            .contains("*(uint64_t *)(&v0) = *(uint64_t *)(r_a64_x1)"),
        "{}",
        recovered.source
    );
    assert!(
        recovered
            .source
            .contains("*(uint64_t *)(r_rax) = *(uint64_t *)(&v0)"),
        "{}",
        recovered.source
    );

    let Some(compiler): Option<PathBuf> =
        find_program("cc").or_else(|| find_program("gcc").or_else(|| find_program("clang")))
    else {
        eprintln!("skipping d-register behavioral check: no host C compiler");
        return;
    };
    let scratch: tempfile::TempDir =
        tempfile::tempdir().expect("create d-register scratch directory");
    let source_path: PathBuf = scratch.path().join("dreg_recovered.c");
    let driver_path: PathBuf = scratch.path().join("dreg_driver.c");
    let exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        "dreg_driver.exe"
    } else {
        "dreg_driver"
    });
    let renamed: String =
        recovered
            .source
            .replacen("uint64_t recovered(", "uint64_t dreg_recovered(", 1);
    std::fs::write(&source_path, renamed).expect("write recovered d-register source");
    std::fs::write(
        &driver_path,
        "#include <stdint.h>\n#include <string.h>\n\
         extern uint64_t dreg_recovered(uint64_t d, uint64_t s, uint64_t n);\n\
         int main(void) {\n\
         \x20   uint64_t src[7]; uint64_t dst[7];\n\
         \x20   for (int i = 0; i < 7; i++) { src[i] = 0x1111111100000000ULL * (i + 1) + i; dst[i] = 0; }\n\
         \x20   dreg_recovered((uint64_t)(uintptr_t)dst, (uint64_t)(uintptr_t)src, 7);\n\
         \x20   return memcmp(dst, src, sizeof(src)) == 0 ? 0 : 1;\n\
         }\n",
    )
    .expect("write d-register driver");
    run_tool(
        &compiler,
        vec![
            "-O1".into(),
            "-fno-strict-aliasing".into(),
            source_path.as_os_str().to_owned(),
            driver_path.as_os_str().to_owned(),
            "-o".into(),
            exe_path.as_os_str().to_owned(),
        ],
    );
    let no_args: [OsString; 0] = [];
    let outcome: CapturedOutput =
        run_captured(&exe_path, &no_args, Duration::from_secs(30), 1 << 20)
            .expect("spawn d-register driver")
            .expect("d-register driver timeout");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "recovered d-register copy diverged from the reference buffer"
    );
}

#[test]
fn aarch64_cross_width_fmov_zero_extends_the_low_lane() {
    let bytes: [u8; 16] = [
        0x01, 0x00, 0x67, 0x9e, 0x22, 0x40, 0x20, 0x1e, 0x40, 0x40, 0x60, 0x1e, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let r: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("cross-width fmov sequence");
    assert!(
        r.source.contains("& 0xffffffffULL") || r.source.contains("(uint32_t)"),
        "the single-precision fmov must zero-extend the low 32 bits, not copy the full register: {}",
        r.source
    );
}

#[test]
fn aarch64_scalar_fmaxnm_and_fminnm_recover_as_ieee_num_builtins() {
    let max_single: [u8; 8] = [0x00, 0x68, 0x21, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let min_double: [u8; 8] = [0x00, 0x78, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let single: LeafRecovery =
        recover_aarch64_function(&max_single, 0).expect("aarch64 fmaxnm single");
    assert!(
        single.source.contains("__builtin_fmaxf"),
        "single-precision fmaxnm must recover as the ieee maxnum builtin: {}",
        single.source
    );
    assert_eq!(single.fp_params.len(), 2);
    assert_eq!(single.return_width_bits, 32);
    let double: LeafRecovery =
        recover_aarch64_function(&min_double, 0).expect("aarch64 fminnm double");
    assert!(
        double.source.contains("__builtin_fmin("),
        "double-precision fminnm must recover as the ieee minnum builtin: {}",
        double.source
    );
    assert_eq!(double.fp_params.len(), 2);
    assert_eq!(double.return_width_bits, 64);
}

#[test]
fn aarch64_scalar_fma_recovers_with_correct_input_negations() {
    let ret: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    let cases: [(u32, &str, bool, bool); 5] = [
        (0x1f01_0800, "__builtin_fmaf(", false, false),
        (0x1f01_8800, "__builtin_fmaf(", true, false),
        (0x1f21_0800, "__builtin_fmaf(", true, true),
        (0x1f21_8800, "__builtin_fmaf(", false, true),
        (0x1f41_0800, "__builtin_fma(", false, false),
    ];
    for (word, builtin, neg_mul_lhs, neg_addend) in cases {
        let mut bytes: Vec<u8> = word.to_le_bytes().to_vec();
        bytes.extend_from_slice(&ret);
        let recovered: LeafRecovery =
            recover_aarch64_function(&bytes, 0).expect("aarch64 fused multiply-add");
        assert_eq!(recovered.fp_params.len(), 3, "{builtin}");
        let call: &str = recovered
            .source
            .split(builtin)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {builtin} in {}", recovered.source));
        let mut depth: i32 = 1;
        let mut parts: Vec<String> = vec![String::new()];
        for ch in call.chars() {
            match ch {
                '(' => {
                    depth += 1;
                    parts.last_mut().expect("current arg").push(ch);
                }
                ')' if depth == 1 => break,
                ')' => {
                    depth -= 1;
                    parts.last_mut().expect("current arg").push(ch);
                }
                ',' if depth == 1 => parts.push(String::new()),
                _ => parts.last_mut().expect("current arg").push(ch),
            }
        }
        let parts: Vec<&str> = parts.iter().map(|part: &String| part.trim()).collect();
        assert_eq!(parts.len(), 3, "three fma arguments in `{call}`");
        assert_eq!(
            parts[0].starts_with('-'),
            neg_mul_lhs,
            "multiplicand negation for {word:#010x} in `{}`",
            parts.join(" | ")
        );
        assert_eq!(
            parts[2].starts_with('-'),
            neg_addend,
            "addend negation for {word:#010x} in `{}`",
            parts.join(" | ")
        );
        assert!(
            !parts[1].starts_with('-'),
            "the multiplier must never be negated for {word:#010x} in `{}`",
            parts.join(" | ")
        );
    }
}

#[test]
fn aarch64_scalar_fp_compare_recovers_ordered_unordered_and_select() {
    let ret: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
    let ordered_lt: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0xe0, 0x57, 0x9f, 0x1a];
    let unordered_nlt: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0xe0, 0x47, 0x9f, 0x1a];
    let is_nan: [u8; 8] = [0x00, 0x20, 0x20, 0x1e, 0xe0, 0x77, 0x9f, 0x1a];
    let select_min: [u8; 8] = [0x00, 0x20, 0x21, 0x1e, 0x00, 0x4c, 0x21, 0x1e];

    let mut lt_bytes: Vec<u8> = ordered_lt.to_vec();
    lt_bytes.extend_from_slice(&ret);
    let lt: LeafRecovery = recover_aarch64_function(&lt_bytes, 0).expect("fcmp + cset mi");
    assert!(
        lt.source.contains('<') && !lt.source.contains("!("),
        "fcmp + cset mi must recover an ordered less-than: {}",
        lt.source
    );

    let mut nlt_bytes: Vec<u8> = unordered_nlt.to_vec();
    nlt_bytes.extend_from_slice(&ret);
    let nlt: LeafRecovery = recover_aarch64_function(&nlt_bytes, 0).expect("fcmp + cset pl");
    assert!(
        nlt.source.contains("!("),
        "fcmp + cset pl must recover the unordered complement of less-than: {}",
        nlt.source
    );

    let mut nan_bytes: Vec<u8> = is_nan.to_vec();
    nan_bytes.extend_from_slice(&ret);
    let nan: LeafRecovery = recover_aarch64_function(&nan_bytes, 0).expect("fcmp x,x + cset vs");
    assert!(
        nan.source.contains("!="),
        "fcmp of a register with itself + cset vs must recover an unordered test: {}",
        nan.source
    );

    let mut sel_bytes: Vec<u8> = select_min.to_vec();
    sel_bytes.extend_from_slice(&ret);
    let sel: LeafRecovery = recover_aarch64_function(&sel_bytes, 0).expect("fcmp + fcsel mi");
    assert!(
        sel.source.contains('?') && sel.source.contains('<'),
        "fcmp + fcsel mi must recover a conditional select on an ordered less-than: {}",
        sel.source
    );
    assert_eq!(sel.fp_params.len(), 2);
    assert!(sel.returns_fp.is_some());
    assert_eq!(sel.return_width_bits, 32);
}

#[test]
fn aarch64_fp_return_survives_an_incidental_fp_compare_side_effect() {
    let bytes: [u8; 20] = [
        0x00, 0x28, 0x21, 0x1e, 0x08, 0x20, 0x20, 0x1e, 0xe8, 0x57, 0x9f, 0x1a, 0x08, 0x00, 0x00,
        0xb9, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("fp add with a compare stored to a pointer");
    assert!(
        recovered.returns_fp.is_some(),
        "a function that returns its fp sum must not be reclassified as int just because it materializes an fp comparison into a stored flag: {}",
        recovered.source
    );
    assert_eq!(recovered.return_width_bits, 32);
}

#[test]
fn atomics_and_out_of_subset_integer_ops_reject_explicitly() {
    let atomics: [u8; 12] = [
        0x01, 0x7c, 0x5f, 0xc8, 0x01, 0x7c, 0x02, 0xc8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let widening_multiply_accumulate: [u8; 8] = [0x20, 0x08, 0x20, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    for bytes in [&atomics[..], &widening_multiply_accumulate[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("unsupported aarch64 class");
        assert!(
            format!("{error:?}").contains("aarch64 reject: unsupported instruction"),
            "{error:?}"
        );
    }
}

#[test]
fn neon_register_form_packed_arithmetic_lifts() {
    let cases: [(&[u8], &str, &str); 9] = [
        (
            &[0x00, 0xd4, 0x21, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 + v1",
        ),
        (
            &[0x00, 0xd4, 0xa1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 - v1",
        ),
        (
            &[0x00, 0xdc, 0x21, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f32x4",
            "v0 = v0 * v1",
        ),
        (
            &[0x20, 0x84, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v1 + v0",
        ),
        (
            &[0x20, 0x9c, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v1 * v0",
        ),
        (
            &[0x00, 0x84, 0xa1, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i32x4",
            "v0 = v0 - v1",
        ),
        (
            &[0x00, 0xd4, 0x61, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f64x2",
            "v0 = v0 + v1",
        ),
        (
            &[0x00, 0xdc, 0x61, 0x6e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_f64x2",
            "v0 = v0 * v1",
        ),
        (
            &[0x20, 0x84, 0x60, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            "recovered_i16x8",
            "v0 = v1 + v0",
        ),
    ];
    for (bytes, ty, op) in cases {
        let recovered: LeafRecovery = recover_aarch64_function(bytes, 0).expect("neon arithmetic");
        assert!(
            recovered.source.contains(ty),
            "missing {ty} in {}",
            recovered.source
        );
        assert!(
            recovered
                .source
                .contains("__attribute__((vector_size(16)))"),
            "{}",
            recovered.source
        );
        assert!(
            recovered.source.contains(op),
            "missing {op} in {}",
            recovered.source
        );
        assert!(
            recovered.source.contains("return v0;"),
            "{}",
            recovered.source
        );
        assert_eq!(recovered.return_width_bits, 128);
        assert!(recovered.rust_source.is_none());
    }
}

#[test]
fn neon_vector_load_store_and_dup_lift() {
    let store_add: [u8; 20] = [
        0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x00, 0x00, 0x80,
        0x3d, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&store_add, 0).expect("neon store-add");
    assert!(
        recovered
            .source
            .contains("void recovered(uint64_t a0, uint64_t a1, uint64_t a2)")
    );
    assert_eq!(recovered.source.matches("*(recovered_f32x4*)").count(), 3);
    assert!(recovered.source.contains("v0 = v0 + v1;"));
    assert!(recovered.source.contains("return;"));
    assert_eq!(recovered.return_width_bits, 0);

    let copyq: [u8; 12] = [
        0x20, 0x00, 0xc0, 0x3d, 0x00, 0x00, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let copy: LeafRecovery = recover_aarch64_function(&copyq, 0).expect("neon copy");
    assert_eq!(copy.source.matches("*(recovered_i8x16*)").count(), 2);
    assert!(copy.source.contains("void recovered("));

    let splat: [u8; 8] = [0x00, 0x0c, 0x04, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let broadcast: LeafRecovery = recover_aarch64_function(&splat, 0).expect("neon dup");
    assert_eq!(broadcast.params, vec![PseudoReg::Rax]);
    assert!(
        broadcast.source.contains(
            "(recovered_i32x4){(int32_t)r_rax, (int32_t)r_rax, (int32_t)r_rax, (int32_t)r_rax}"
        ),
        "{}",
        broadcast.source
    );
    assert!(broadcast.source.contains("return v0;"));
}

#[test]
fn neon_out_of_subset_forms_reject_explicitly() {
    let vector_mov: [u8; 8] = [0x20, 0x1c, 0xa1, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let indexed_fmla: [u8; 8] = [0x10, 0x11, 0x80, 0x0f, 0xc0, 0x03, 0x5f, 0xd6];
    let ld1_single: [u8; 8] = [0x68, 0x79, 0x40, 0x4c, 0xc0, 0x03, 0x5f, 0xd6];
    let reduction: [u8; 8] = [0x00, 0x38, 0x30, 0x0e, 0xc0, 0x03, 0x5f, 0xd6];
    for bytes in [
        &vector_mov[..],
        &indexed_fmla[..],
        &ld1_single[..],
        &reduction[..],
    ] {
        let error =
            recover_aarch64_function(bytes, 0).expect_err("out-of-subset neon form must reject");
        assert!(
            format!("{error:?}").contains("aarch64 reject:"),
            "{error:?}"
        );
    }
}

#[test]
fn neon_recovered_sources_recompile_to_matching_words() {
    let Some(clang): Option<PathBuf> = find_program("clang") else {
        eprintln!("skipping neon recompile: clang is unavailable");
        return;
    };
    let Some(objdump): Option<PathBuf> = find_program("llvm-objdump") else {
        eprintln!("skipping neon recompile: llvm-objdump is unavailable");
        return;
    };
    let cases: [(&[u8], &[&str]); 5] = [
        (
            &[0x00, 0xd4, 0x21, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4e21d400"],
        ),
        (
            &[0x20, 0x84, 0xa0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4ea08420"],
        ),
        (
            &[0x00, 0x0c, 0x04, 0x4e, 0xc0, 0x03, 0x5f, 0xd6],
            &["4e040c00"],
        ),
        (
            &[
                0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x00, 0x00,
                0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            &["3dc00020", "3dc00041", "4e21d400", "3d800000"],
        ),
        (
            &[
                0x20, 0x00, 0xc0, 0x3d, 0x41, 0x00, 0xc0, 0x3d, 0x00, 0xd4, 0x21, 0x4e, 0x61, 0x00,
                0xc0, 0x3d, 0x00, 0xdc, 0x21, 0x6e, 0x00, 0x00, 0x80, 0x3d, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            &["3dc00020", "4e21d400", "6e21dc00", "3d800000"],
        ),
    ];
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create neon scratch directory");
    for (index, (bytes, expected)) in cases.into_iter().enumerate() {
        let recovered: LeafRecovery =
            recover_aarch64_function(bytes, 0).expect("recover neon function");
        let source_path: PathBuf = scratch.path().join(format!("neon_{index}.c"));
        let object_path: PathBuf = scratch.path().join(format!("neon_{index}.o"));
        std::fs::write(&source_path, recovered.source).expect("write recovered neon source");
        run_tool(
            &clang,
            vec![
                "--target=aarch64-linux-gnu".into(),
                "-O2".into(),
                "-ffreestanding".into(),
                "-c".into(),
                source_path.as_os_str().to_owned(),
                "-o".into(),
                object_path.as_os_str().to_owned(),
            ],
        );
        let listing: CapturedOutput = run_tool(
            &objdump,
            vec!["-d".into(), object_path.as_os_str().to_owned()],
        );
        let listing: String = String::from_utf8(listing.stdout).expect("utf8 neon listing");
        for word in expected {
            assert!(
                listing.contains(word),
                "recompiled neon function {index} is missing {word}\n{listing}"
            );
        }
    }
}

#[test]
fn clang_and_llvm_cross_check_committed_words_and_recompiled_add() {
    let Some(clang): Option<PathBuf> = find_program("clang") else {
        eprintln!("skipping aarch64 compiler cross-check: clang is unavailable");
        return;
    };
    let Some(objdump): Option<PathBuf> = find_program("llvm-objdump") else {
        eprintln!("skipping aarch64 compiler cross-check: llvm-objdump is unavailable");
        return;
    };
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create aarch64 scratch directory");
    let original_c: PathBuf = scratch.path().join("original.c");
    let original_o: PathBuf = scratch.path().join("original.o");
    let recovered_c: PathBuf = scratch.path().join("recovered.c");
    let recovered_o: PathBuf = scratch.path().join("recovered.o");
    std::fs::write(
        &original_c,
        "long add3(long a,long b,long c){return a+b+c;} struct triple{long a;long b;long c;}; struct triple make3(long a,long b,long c){struct triple x={a,b,c};return x;}",
    )
    .expect("write aarch64 source");
    run_tool(
        &clang,
        vec![
            "--target=aarch64-linux-gnu".into(),
            "-O2".into(),
            "-ffreestanding".into(),
            "-c".into(),
            original_c.as_os_str().to_owned(),
            "-o".into(),
            original_o.as_os_str().to_owned(),
        ],
    );
    let listing: CapturedOutput = run_tool(
        &objdump,
        vec!["-d".into(), original_o.as_os_str().to_owned()],
    );
    let listing: String = String::from_utf8(listing.stdout).expect("utf8 llvm listing");
    for word in ["8b000028", "8b020100", "a9000500", "f9000902"] {
        assert!(listing.contains(word), "missing {word} in {listing}");
    }
    let add3: [u8; 12] = [
        0x28, 0x00, 0x00, 0x8b, 0x00, 0x01, 0x02, 0x8b, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&add3, 0).expect("recover add3");
    std::fs::write(&recovered_c, recovered.source).expect("write recovered aarch64 source");
    run_tool(
        &clang,
        vec![
            "--target=aarch64-linux-gnu".into(),
            "-O2".into(),
            "-ffreestanding".into(),
            "-c".into(),
            recovered_c.as_os_str().to_owned(),
            "-o".into(),
            recovered_o.as_os_str().to_owned(),
        ],
    );
    let recovered_listing: CapturedOutput = run_tool(
        &objdump,
        vec!["-d".into(), recovered_o.as_os_str().to_owned()],
    );
    let recovered_listing: String =
        String::from_utf8(recovered_listing.stdout).expect("utf8 recovered listing");
    assert!(
        recovered_listing.contains("8b000028"),
        "{recovered_listing}"
    );
    assert!(
        recovered_listing.contains("8b020100"),
        "{recovered_listing}"
    );
}

#[test]
fn oversized_input_rejects_before_decode() {
    let bytes: Vec<u8> = vec![0xff; 4097 * 4];
    let error = recover_aarch64_function(&bytes, 0).expect_err("oversized aarch64 body");
    assert!(
        format!("{error:?}").contains("aarch64 reject: instruction bytes exceed the bounded lift"),
        "{error:?}"
    );
}

#[test]
fn stack_adjustment_outside_frame_edges_rejects() {
    let bytes: [u8; 12] = [
        0xe0, 0x03, 0x01, 0xaa, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error = recover_aarch64_function(&bytes, 0).expect_err("mid-body stack adjustment");
    assert!(
        format!("{error:?}").contains("outside a recognized prologue or epilogue"),
        "{error:?}"
    );
}

#[test]
fn incomplete_and_negative_stack_epilogues_reject() {
    let missing: [u8; 12] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let under_restored: [u8; 16] = [
        0xff, 0x83, 0x00, 0xd1, 0xe0, 0x03, 0x01, 0xaa, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f,
        0xd6,
    ];
    let negative: [u8; 20] = [
        0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe0, 0x03, 0x01, 0xaa, 0xfd, 0x7b, 0xff,
        0xa8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for bytes in [&missing[..], &under_restored[..], &negative[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("invalid stack epilogue");
        assert!(
            format!("{error:?}").contains("stack epilogue")
                || format!("{error:?}").contains("stack restoration"),
            "{error:?}"
        );
    }
}

#[test]
fn intervening_write_never_compares_the_overwritten_nzcv_operand() {
    let bytes: [u8; 28] = [
        0x1f, 0x00, 0x01, 0xeb, 0xe0, 0x03, 0x02, 0xaa, 0x6c, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80,
        0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery =
        recover_aarch64_function(&bytes, 0).expect("clobbered compare operand recovers");
    let overwrite: usize = recovered
        .source
        .find("r_rax = r_a64_x2;")
        .unwrap_or_else(|| panic!("{}", recovered.source));
    assert!(
        recovered.source[..overwrite]
            .contains("sel_cc_0 = (int64_t)(int64_t)(r_rax) > (int64_t)(int64_t)(r_a64_x1);"),
        "{}",
        recovered.source
    );
    assert!(
        !recovered.source[overwrite..].contains("r_a64_x1"),
        "{}",
        recovered.source
    );
}

#[test]
fn unresolved_call_infers_only_register_arguments() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("unresolved bl");
    assert_eq!(recovered.params.len(), 8);
    assert!(!recovered.params.contains(&PseudoReg::A64Stack0));
}

#[test]
fn legacy_x86_entry_rejects_aapcs64() {
    let error = recover_leaf_function_abi(&[0xc3], 0, PseudoAbi::Aapcs64)
        .expect_err("aapcs64 in x86 entry");
    assert!(format!("{error:?}").contains("aapcs64"), "{error:?}");
}

#[test]
fn legacy_x86_object_entry_rejects_aapcs64_before_probing() {
    let error = recover_leaf_function_in_object(&[], &[0xc3], 0, PseudoAbi::Aapcs64, &[])
        .expect_err("aapcs64 in x86 object entry");
    assert!(format!("{error:?}").contains("aapcs64"), "{error:?}");
}

#[test]
fn resolved_call_rejects_arguments_beyond_bounded_stack_slots() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
    let calls: [ResolvedCall; 1] = [ResolvedCall {
        target: 0,
        name: None,
        arg_count: 17,
    }];
    let error = recover_aarch64_function_with_calls(&bytes, 0, &calls)
        .expect_err("too many resolved aapcs64 arguments");
    assert!(
        format!("{error:?}").contains("resolved call argument count exceeds"),
        "{error:?}"
    );
}

#[test]
fn duplicate_resolved_call_targets_reject() {
    let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6];
    let calls: [ResolvedCall; 2] = [
        ResolvedCall {
            target: 0,
            name: None,
            arg_count: 1,
        },
        ResolvedCall {
            target: 0,
            name: None,
            arg_count: 9,
        },
    ];
    let error = recover_aarch64_function_with_calls(&bytes, 0, &calls)
        .expect_err("duplicate resolved call target");
    assert!(
        format!("{error:?}").contains("resolved call targets contain duplicates"),
        "{error:?}"
    );
}

#[test]
fn subs_branch_uses_pre_subtraction_operands() {
    let bytes: [u8; 24] = [
        0x00, 0x04, 0x00, 0xf1, 0x60, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let recovered: LeafRecovery = recover_aarch64_function(&bytes, 0).expect("subs branch");
    assert!(recovered.source.contains("r_a64_flag_lhs"));
    assert!(recovered.source.contains("r_a64_flag_rhs"));
}

#[test]
fn cmn_and_tst_reject_conditions_that_need_cv() {
    let cmn_lt: [u8; 24] = [
        0x1f, 0x14, 0x00, 0xb1, 0x6b, 0x00, 0x00, 0x54, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let tst_hs: [u8; 24] = [
        0x1f, 0x00, 0x01, 0xea, 0x62, 0x00, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f,
        0xd6, 0x60, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    for bytes in [&cmn_lt[..], &tst_hs[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("condition needs cv flags");
        assert!(
            format!("{error:?}").contains("condition is undefined for the tracked nzcv source"),
            "{error:?}"
        );
    }
}
