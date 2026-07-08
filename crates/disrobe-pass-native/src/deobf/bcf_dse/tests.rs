use std::collections::BTreeMap;

use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ecx, rax};
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

#[test]
fn an_unresolved_indirect_branch_elsewhere_in_the_section_suppresses_the_single_predecessor_fold() {
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
    asm.jmp(rax)
        .expect("register-indirect jmp elsewhere in the same section");
    let bytes: Vec<u8> = assemble(&mut asm);
    let branch_address: u64 = find_ip(&bytes, Mnemonic::Je);

    let result: BogusBranch = analyze_branch_backward(64, BASE, &bytes, branch_address)
        .expect("a genuine predicate is still built even though the fold is suppressed");
    assert_eq!(
        result.result,
        OpaqueResult::DataDependent,
        "the mov eax,5 predecessor can no longer be folded in as a mandatory path constraint \
         once the section also contains an indirect branch that could plausibly target the \
         same block from somewhere the direct-edge view cannot see, so eax must stay \
         unconstrained instead of proving a false AlwaysTaken"
    );
    assert!(result.dead_target.is_none());
    assert!(result.live_target.is_none());
}

#[test]
fn section_has_unresolved_edges_is_false_for_a_fully_direct_edge_section() {
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

    let insns: Vec<Instruction> = decode_all(64, BASE, &bytes);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    assert!(
        !section_has_unresolved_edges(&insns, &index),
        "every branch in this section has a near target that lands on a decoded instruction"
    );
}

#[test]
fn section_has_unresolved_edges_is_true_for_an_indirect_branch() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, 5i32).unwrap();
    asm.jmp(rax).expect("register-indirect jmp");
    let bytes: Vec<u8> = assemble(&mut asm);

    let insns: Vec<Instruction> = decode_all(64, BASE, &bytes);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    assert!(
        section_has_unresolved_edges(&insns, &index),
        "an indirect branch can target anywhere in the section, so no block's predecessor \
         set can be trusted as complete purely from the direct-edge view"
    );
}

#[test]
fn section_has_unresolved_edges_is_true_for_a_direct_branch_whose_target_misses_the_decode() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut target: CodeLabel = asm.create_label();
    asm.jmp(target).unwrap();
    asm.nop().unwrap();
    asm.set_label(&mut target).unwrap();
    asm.ret().unwrap();
    let full_bytes: Vec<u8> = assemble(&mut asm);

    let mut decoder: Decoder<'_> = Decoder::with_ip(64, &full_bytes, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    decoder.decode_out(&mut insn);
    assert_eq!(
        insn.mnemonic(),
        Mnemonic::Jmp,
        "the jmp is the first assembled instruction"
    );
    let truncated_len: usize = decoder.position();
    assert!(truncated_len > 0 && truncated_len < full_bytes.len());
    let truncated: &[u8] = &full_bytes[..truncated_len];

    let insns: Vec<Instruction> = decode_all(64, BASE, truncated);
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    assert!(
        section_has_unresolved_edges(&insns, &index),
        "the jmp's near target falls past the end of the decoded stream, so it cannot be \
         mapped to any known block and must not be silently dropped"
    );
}
