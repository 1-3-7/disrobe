use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ecx};

use super::*;

const BASE: u64 = 0x2000;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble block")
}

#[test]
fn always_even_opaque_predicate_folds_to_taken() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut real: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.imul_2(ecx, eax).unwrap();
    asm.add(ecx, eax).unwrap();
    asm.and(ecx, 1i32).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.je(real).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let branch_only: &[u8] = &bytes[..bytes.len() - 1];
    let result: BogusBranch =
        analyze_block(64, BASE, branch_only).expect("opaque branch analyzable");
    assert_eq!(
        result.result,
        OpaqueResult::AlwaysTaken,
        "x*x + x is always even, so (..)&1 == 0 must be proven always-true"
    );
    assert!(result.dead_target.is_some(), "dead arm must be identified");
    assert!(result.live_target.is_some(), "live arm must be identified");
}

#[test]
fn genuine_comparison_is_not_folded() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.cmp(eax, 100i32).unwrap();
    asm.jb(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_only: &[u8] = &bytes[..bytes.len() - 1];
    let result: BogusBranch = analyze_block(64, BASE, branch_only).expect("comparison analyzable");
    assert_eq!(
        result.result,
        OpaqueResult::DataDependent,
        "eax < 100 is genuinely data-dependent and must never be folded"
    );
    assert!(result.dead_target.is_none());
}

#[test]
fn self_and_complement_is_always_false() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.not(ecx).unwrap();
    asm.and(ecx, eax).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.jne(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_only: &[u8] = &bytes[..bytes.len() - 1];
    let result: BogusBranch = analyze_block(64, BASE, branch_only).expect("analyzable");
    assert_eq!(
        result.result,
        OpaqueResult::AlwaysNotTaken,
        "(~x & x) is always 0, so `jne` on it is never taken"
    );
}
