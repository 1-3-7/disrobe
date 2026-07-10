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
fn neon_atomics_and_out_of_subset_integer_ops_reject_explicitly() {
    let neon: [u8; 8] = [0x20, 0x84, 0xe0, 0x4e, 0xc0, 0x03, 0x5f, 0xd6];
    let atomics: [u8; 12] = [
        0x01, 0x7c, 0x5f, 0xc8, 0x01, 0x7c, 0x02, 0xc8, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let high_multiply: [u8; 8] = [0x09, 0x7d, 0xc9, 0x9b, 0xc0, 0x03, 0x5f, 0xd6];
    for bytes in [&neon[..], &atomics[..], &high_multiply[..]] {
        let error = recover_aarch64_function(bytes, 0).expect_err("unsupported aarch64 class");
        assert!(
            format!("{error:?}").contains("aarch64 reject: unsupported instruction"),
            "{error:?}"
        );
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
fn intervening_write_invalidates_tracked_nzcv_operands() {
    let bytes: [u8; 28] = [
        0x1f, 0x00, 0x01, 0xeb, 0xe0, 0x03, 0x02, 0xaa, 0x6c, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80,
        0xd2, 0xc0, 0x03, 0x5f, 0xd6, 0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let error = recover_aarch64_function(&bytes, 0).expect_err("stale nzcv operands");
    assert!(
        format!("{error:?}").contains("conditional branch lacks live nzcv state"),
        "{error:?}"
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
