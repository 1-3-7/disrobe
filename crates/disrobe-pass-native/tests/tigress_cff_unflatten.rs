//! Tigress CFF deobfuscation tests.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    CffUnflattenReport, DeobfBits, ObfuscatorFamily, detect_obfuscators, unflatten_tigress,
};
use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ecx};

const BASE: u64 = 0x4000;

#[test]
fn tigress_cff_marker_detected() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..16].copy_from_slice(b"_TIGRESS_flatten");
    let hits = detect_obfuscators(&buf);
    assert!(
        hits.iter()
            .any(|h| h.family == ObfuscatorFamily::TigressCff)
    );
}

#[test]
fn tigress_unflatten_recovers_self_authored_register_state_dispatch() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case0: CodeLabel = asm.create_label();
    let mut case1: CodeLabel = asm.create_label();
    let mut case2: CodeLabel = asm.create_label();

    asm.mov(ecx, 0i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.je(case0).unwrap();
    asm.cmp(ecx, 1i32).unwrap();
    asm.je(case1).unwrap();
    asm.cmp(ecx, 2i32).unwrap();
    asm.je(case2).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut case0).unwrap();
    asm.mov(eax, 3i32).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case1).unwrap();
    asm.add(eax, 4i32).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case2).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let report: CffUnflattenReport = unflatten_tigress(DeobfBits::Bits64, BASE, &bytes, BASE);
    assert!(
        report.fully_recovered,
        "register-state dispatch must be recovered: {report:?}"
    );
    assert_eq!(report.recovered_blocks, 3);
    assert_eq!(report.state_variable_register.as_deref(), Some("ECX"));
}

#[test]
#[ignore = "no real Tigress-flattened binary is committed; the cmp-chain shape is validated on self-authored bytes above"]
fn real_tigress_sample_unflatten() {}
