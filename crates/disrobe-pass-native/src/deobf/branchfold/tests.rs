use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ebx, ecx, edi, edx};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

use super::*;
use crate::stub_emu::cpu::NoopHost;
use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

const BASE: u64 = 0x2000;
const CODE_REGION: u64 = 0x40_0000;
const CODE_SIZE: u64 = 0x4000;
const STEP_CAP: u64 = 4096;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble block")
}

fn decode(block: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, block, BASE, DecoderOptions::NONE);
    let mut insns: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        insns.push(insn);
    }
    insns
}

const SAMPLES: [u64; 6] = [0, 1, 7, 0x1234_5678, 0xFFFF_FFFF, 0x8000_0000];

fn seed_domain() -> Vec<Vec<(Reg, u64)>> {
    let mut out: Vec<Vec<(Reg, u64)>> = Vec::new();
    for &a in &SAMPLES {
        for &b in &SAMPLES {
            out.push(vec![
                (Reg::Rax, a),
                (Reg::Rbx, b),
                (Reg::Rcx, a ^ b),
                (Reg::Rdx, a.wrapping_add(b)),
            ]);
        }
    }
    out
}

fn build_probe(body: &[Instruction]) -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("probe assembler");
    let mut taken: CodeLabel = asm.create_label();
    let mut done: CodeLabel = asm.create_label();
    for insn in &body[..body.len() - 1] {
        asm.add_instruction(*insn).expect("body insn");
    }
    let branch: &Instruction = body.last().expect("branch");
    emit_branch_to_label(&mut asm, branch.mnemonic(), taken);
    asm.mov(edi, 0u32).expect("fall marker");
    asm.jmp(done).expect("skip taken");
    asm.set_label(&mut taken).expect("taken label");
    asm.mov(edi, 1u32).expect("taken marker");
    asm.set_label(&mut done).expect("done label");
    asm.int3().expect("halt");
    asm.assemble(CODE_REGION).expect("assemble probe")
}

fn emit_branch_to_label(asm: &mut CodeAssembler, mnemonic: Mnemonic, label: CodeLabel) {
    match mnemonic {
        Mnemonic::Je => asm.je(label),
        Mnemonic::Jne => asm.jne(label),
        Mnemonic::Jb => asm.jb(label),
        Mnemonic::Jbe => asm.jbe(label),
        Mnemonic::Ja => asm.ja(label),
        Mnemonic::Jae => asm.jae(label),
        Mnemonic::Jl => asm.jl(label),
        Mnemonic::Jle => asm.jle(label),
        Mnemonic::Jg => asm.jg(label),
        Mnemonic::Jge => asm.jge(label),
        other => panic!("unsupported probe branch {other:?}"),
    }
    .expect("emit branch");
}

fn taken_edge_under_emulation(probe: &[u8], seed: &[(Reg, u64)]) -> bool {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem.map(CODE_REGION, CODE_SIZE, Perm::RX).expect("map");
    cpu.mem.write_unchecked(CODE_REGION, probe);
    for &(reg, value) in seed {
        cpu.regs.set(reg, value);
    }
    cpu.regs.rip = CODE_REGION;
    let mut host: NoopHost = NoopHost;
    let _ = cpu.run(&mut host, STEP_CAP).expect("run probe");
    cpu.regs.get(Reg::Rdi) == 1
}

fn assert_fold_matches_emulation(block: &[u8], outcome: &BranchFoldOutcome) {
    let probe: Vec<u8> = build_probe(&decode(block));
    let expect_taken: bool = matches!(outcome.finding.verdict, FoldVerdict::AlwaysTaken);
    for seed in seed_domain() {
        let actual_taken: bool = taken_edge_under_emulation(&probe, &seed);
        assert_eq!(
            actual_taken, expect_taken,
            "fold verdict {:?} disagreed with real stub_emu execution for seed {seed:?}",
            outcome.finding.verdict
        );
    }
}

#[test]
fn constant_condition_after_copy_propagation_folds_to_taken() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(eax, 5u32).unwrap();
    asm.mov(ebx, eax).unwrap();
    asm.mov(ecx, 2u32).unwrap();
    asm.add(ecx, 3u32).unwrap();
    asm.cmp(ebx, ecx).unwrap();
    asm.je(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    let outcome: BranchFoldOutcome = fold_block(64, BASE, block).expect("constant branch folds");
    assert_eq!(outcome.finding.kind, FoldKind::ConstantCondition);
    assert_eq!(outcome.finding.verdict, FoldVerdict::AlwaysTaken);
    assert_eq!(outcome.finding.free_variables, 0);
    assert_fold_matches_emulation(block, &outcome);
}

#[test]
fn opaque_identity_always_even_folds_to_taken() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.imul_2(ecx, eax).unwrap();
    asm.add(ecx, eax).unwrap();
    asm.and(ecx, 1i32).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.je(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    let outcome: BranchFoldOutcome = fold_block(64, BASE, block).expect("opaque branch folds");
    assert_eq!(outcome.finding.kind, FoldKind::OpaqueIdentity);
    assert_eq!(outcome.finding.verdict, FoldVerdict::AlwaysTaken);
    assert!(outcome.finding.free_variables >= 1);
    assert_fold_matches_emulation(block, &outcome);
}

#[test]
fn opaque_self_and_complement_folds_to_not_taken() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.not(ecx).unwrap();
    asm.and(ecx, eax).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.jne(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    let outcome: BranchFoldOutcome = fold_block(64, BASE, block).expect("opaque branch folds");
    assert_eq!(outcome.finding.kind, FoldKind::OpaqueIdentity);
    assert_eq!(outcome.finding.verdict, FoldVerdict::AlwaysNotTaken);
    assert_fold_matches_emulation(block, &outcome);
}

#[test]
fn genuine_comparison_is_never_folded() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.cmp(eax, 100i32).unwrap();
    asm.jb(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    assert!(
        fold_block(64, BASE, block).is_none(),
        "eax < 100 is genuinely data-dependent and must never be folded away"
    );
}

#[test]
fn dead_store_in_folded_body_is_removed_without_changing_branch() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(edx, 0x1111u32).unwrap();
    asm.mov(edx, 0x2222u32).unwrap();
    asm.mov(eax, 9u32).unwrap();
    asm.cmp(eax, 9u32).unwrap();
    asm.je(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    let outcome: BranchFoldOutcome = fold_block(64, BASE, block).expect("constant branch folds");
    assert_eq!(outcome.finding.verdict, FoldVerdict::AlwaysTaken);
    assert!(
        outcome.finding.eliminated_dead_stores >= 1,
        "the overwritten `mov edx,0x1111` must be eliminated as a dead store: {:?}",
        outcome.finding
    );
    assert!(
        outcome.kept_body.len() < 3,
        "kept body must drop the dead store: {:?}",
        outcome.kept_body.len()
    );
    assert_fold_matches_emulation(block, &outcome);
}

#[test]
fn live_store_feeding_the_compare_is_not_dropped() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    asm.mov(eax, 5u32).unwrap();
    asm.cmp(eax, 5u32).unwrap();
    asm.je(taken).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.nop().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let block: &[u8] = &bytes[..bytes.len() - 1];

    let outcome: BranchFoldOutcome = fold_block(64, BASE, block).expect("folds");
    assert_eq!(outcome.finding.eliminated_dead_stores, 0);
    assert_eq!(outcome.kept_body.len(), 1);
}
