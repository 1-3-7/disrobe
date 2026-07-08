use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ecx};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

use super::*;
use crate::deobf::{Bits, OpaqueResult, defeat_bogus_control_flow_deep};

const BASE: u64 = 0x2000;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble function")
}

fn find_ip(bytes: &[u8], mnemonic: Mnemonic) -> u64 {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.mnemonic() == mnemonic {
            return insn.ip();
        }
    }
    panic!("mnemonic {mnemonic:?} not found in decoded stream");
}

#[test]
fn proves_opacity_across_an_unconditional_jump_that_the_single_block_matcher_cannot_see() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut mid: CodeLabel = asm.create_label();
    let mut real: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    asm.mov(eax, 5i32).unwrap();
    asm.jmp(mid).unwrap();
    asm.set_label(&mut mid).unwrap();
    asm.cmp(eax, 5i32).unwrap();
    asm.je(real).unwrap();
    asm.jmp(dead).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.nop().unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Je);

    let fast: Option<BogusBranch> = locate_containing_block(64, BASE, &bytes, branch_address)
        .and_then(|(block_addr, range)| {
            super::super::bcf::analyze_block(64, block_addr, &bytes[range])
        });
    assert!(
        fast.is_none_or(|found| found.result == OpaqueResult::DataDependent),
        "the single-block fast path cannot see the mov eax,5 across the unconditional jump"
    );

    let result: BogusBranch = analyze_branch_backward(64, BASE, &bytes, branch_address)
        .expect("the backward chain crosses the unconditional jump into the defining block");
    assert_eq!(
        result.result,
        OpaqueResult::AlwaysTaken,
        "eax is proven == 5 by an SMT UNSAT check on the negated taken-edge predicate"
    );
    assert!(result.live_target.is_some());
    assert!(result.dead_target.is_some());
}

#[test]
fn genuinely_unconstrained_register_across_a_jump_stays_data_dependent() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut mid: CodeLabel = asm.create_label();
    let mut real: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.jmp(mid).unwrap();
    asm.set_label(&mut mid).unwrap();
    asm.cmp(ecx, 5i32).unwrap();
    asm.je(real).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Je);

    let result: BogusBranch = analyze_branch_backward(64, BASE, &bytes, branch_address)
        .expect("a genuine predicate must still be built and reported, just not folded");
    assert_eq!(
        result.result,
        OpaqueResult::DataDependent,
        "eax is an unconstrained parameter, so ecx == 5 is genuinely data-dependent"
    );
    assert!(result.dead_target.is_none());
}

#[test]
fn single_block_even_predicate_is_still_proven_through_the_smt_path() {
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
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Je);

    let result: BogusBranch =
        analyze_branch_backward(64, BASE, &bytes, branch_address).expect("analyzable");
    assert_eq!(result.result, OpaqueResult::AlwaysTaken);
}

#[test]
fn composed_entrypoint_prefers_the_cheap_fast_pass_when_it_already_resolves() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut real: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.not(ecx).unwrap();
    asm.and(ecx, eax).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.jne(real).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Jne);

    let result: BogusBranch =
        defeat_bogus_control_flow_deep(Bits::Bits64, BASE, &bytes, branch_address)
            .expect("fast pattern-matcher alone resolves this single block");
    assert_eq!(result.result, OpaqueResult::AlwaysNotTaken);
}

#[test]
fn composed_entrypoint_escalates_to_the_deep_pass_when_the_fast_pass_cannot_resolve() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut mid: CodeLabel = asm.create_label();
    let mut real: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    asm.mov(eax, 7i32).unwrap();
    asm.jmp(mid).unwrap();
    asm.set_label(&mut mid).unwrap();
    asm.cmp(eax, 7i32).unwrap();
    asm.jne(dead).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.nop().unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Jne);

    let result: BogusBranch =
        defeat_bogus_control_flow_deep(Bits::Bits64, BASE, &bytes, branch_address)
            .expect("the deep backward+SMT pass resolves what the single-block matcher cannot");
    assert_eq!(result.result, OpaqueResult::AlwaysNotTaken);
}
