use iced_x86::code_asm::{CodeAssembler, eax, ebx, ecx, edx, esi};
use iced_x86::{Encoder, Instruction};

use super::*;
use crate::stub_emu::cpu::{NoopHost, map_buffer};
use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

const BASE: u64 = 0x4000;
const STACK_TOP: u64 = 0x2_0FF0;

fn encode_at(insns: &[Instruction], base: u64) -> Vec<u8> {
    let mut encoder: Encoder = Encoder::new(64);
    let mut ip: u64 = base;
    let mut out: Vec<u8> = Vec::new();
    for insn in insns {
        let mut placed: Instruction = *insn;
        placed.set_ip(ip);
        let len: u32 = encoder.encode(&placed, ip).expect("encode insn") as u32;
        out.extend_from_slice(encoder.take_buffer().as_slice());
        ip += u64::from(len);
    }
    out
}

fn run_to_halt(bytes: &[u8], seeds: &[(Reg, u64)]) -> [u64; 16] {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    map_buffer(&mut cpu.mem, BASE, bytes, Perm::RX).expect("map code");
    cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
    cpu.regs.set(Reg::Rsp, STACK_TOP);
    for (reg, value) in seeds {
        cpu.regs.set(*reg, *value);
    }
    cpu.regs.rip = BASE;
    let end: u64 = BASE + bytes.len() as u64;
    let mut host: NoopHost = NoopHost;
    for _ in 0..4096u32 {
        let ip: u64 = cpu.regs.rip;
        if ip >= end || !cpu.mem.is_mapped(ip) {
            break;
        }
        let _ = cpu.run(&mut host, 1).expect("single step");
    }
    let order: [Reg; 16] = [
        Reg::Rax,
        Reg::Rcx,
        Reg::Rdx,
        Reg::Rbx,
        Reg::Rsp,
        Reg::Rbp,
        Reg::Rsi,
        Reg::Rdi,
        Reg::R8,
        Reg::R9,
        Reg::R10,
        Reg::R11,
        Reg::R12,
        Reg::R13,
        Reg::R14,
        Reg::R15,
    ];
    let mut snapshot: [u64; 16] = [0u64; 16];
    for (i, reg) in order.iter().enumerate() {
        snapshot[i] = cpu.regs.get(*reg);
    }
    snapshot
}

fn assert_observably_equivalent(
    original: &[u8],
    expected_removed: usize,
    seeds_set: &[&[(Reg, u64)]],
) {
    let Some(outcome): Option<DeadFlagOutcome> = clean_block(64, BASE, original) else {
        panic!("clean_block returned None for a block that should simplify");
    };
    assert_eq!(
        outcome.report.eliminated_flag_writes as usize, expected_removed,
        "wrong number of dead flag-writes removed: {:?}",
        outcome.report
    );
    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    assert!(
        cleaned.len() < original.len(),
        "cleaned block must shrink when junk flag-writes are removed: {} -> {}",
        original.len(),
        cleaned.len()
    );
    for seeds in seeds_set {
        let before: [u64; 16] = run_to_halt(original, seeds);
        let after: [u64; 16] = run_to_halt(&cleaned, seeds);
        let skip_rsp: usize = 4;
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            if i == skip_rsp {
                continue;
            }
            assert_eq!(
                b, a,
                "register {i} diverged after dead-flag elimination for seeds {seeds:?}: {b:#x} vs {a:#x}",
            );
        }
    }
}

fn input_domain(reg_a: Reg, reg_b: Reg) -> Vec<Vec<(Reg, u64)>> {
    let probes: [u64; 8] = [0, 1, 2, 5, 7, 0x7f, 0x100, 0xffff_ffff];
    let mut out: Vec<Vec<(Reg, u64)>> = Vec::new();
    for &a in &probes {
        for &b in &probes {
            out.push(vec![(reg_a, a), (reg_b, b)]);
        }
    }
    out
}

#[test]
fn junk_test_before_real_cmp_is_dead_and_removed() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.test(esi, esi).unwrap();
    asm.cmp(eax, ebx).unwrap();
    asm.setl(iced_x86::code_asm::dl).unwrap();
    asm.movzx(edx, iced_x86::code_asm::dl).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let domain: Vec<Vec<(Reg, u64)>> = input_domain(Reg::Rax, Reg::Rbx);
    let refs: Vec<&[(Reg, u64)]> = domain.iter().map(Vec::as_slice).collect();
    assert_observably_equivalent(&bytes, 1, &refs);
}

#[test]
fn multiple_dead_flag_writes_collapse() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.cmp(ecx, 3i32).unwrap();
    asm.test(esi, esi).unwrap();
    asm.cmp(eax, ebx).unwrap();
    asm.sete(iced_x86::code_asm::dl).unwrap();
    asm.movzx(edx, iced_x86::code_asm::dl).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: DeadFlagOutcome = clean_block(64, BASE, &bytes).expect("simplify");
    assert_eq!(
        outcome.report.eliminated_flag_writes, 2,
        "both the cmp ecx,3 and test esi,esi are clobbered before any read: {:?}",
        outcome.report
    );

    let domain: Vec<Vec<(Reg, u64)>> = input_domain(Reg::Rax, Reg::Rbx);
    let refs: Vec<&[(Reg, u64)]> = domain.iter().map(Vec::as_slice).collect();
    assert_observably_equivalent(&bytes, 2, &refs);
}

#[test]
fn live_flag_consumer_blocks_removal() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.cmp(eax, ebx).unwrap();
    asm.sete(iced_x86::code_asm::dl).unwrap();
    asm.movzx(edx, iced_x86::code_asm::dl).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    assert!(
        clean_block(64, BASE, &bytes).is_none(),
        "the only cmp feeds the setcc that follows; it is live and must not be removed",
    );
}

#[test]
fn cmp_live_out_at_block_end_is_not_removed() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, 1i32).unwrap();
    asm.cmp(eax, ebx).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    assert!(
        clean_block(64, BASE, &bytes).is_none(),
        "a trailing cmp's flags are live-out by default and cannot be proven dead",
    );
}

#[test]
fn dead_cmp_when_caller_declares_flags_dead_out() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, 1i32).unwrap();
    asm.cmp(eax, ebx).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: DeadFlagOutcome =
        clean_block_with_live_out(64, BASE, &bytes, 0).expect("flags dead-out folds the cmp");
    assert_eq!(outcome.report.eliminated_flag_writes, 1);
}

#[test]
fn empty_and_invalid_blocks_yield_none() {
    assert!(clean_block(64, BASE, &[]).is_none());
    assert!(clean_block(64, BASE, &[0xFF, 0xFF, 0xFF]).is_none());
}
