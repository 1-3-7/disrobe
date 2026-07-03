use iced_x86::code_asm::{CodeAssembler, eax, ebx, ecx, edi, edx, esi, r8d};
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

fn assert_observably_equivalent(original: &[u8], seeds_set: &[&[(Reg, u64)]]) {
    let Some(outcome): Option<CopyPropOutcome> = clean_block(64, BASE, original) else {
        panic!("clean_block returned None for a block it should simplify");
    };
    assert!(
        outcome.report.changed,
        "expected a simplification but the report says nothing changed: {:?}",
        outcome.report
    );
    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    assert!(
        cleaned.len() <= original.len(),
        "cleaned block should not grow: {} -> {}",
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
                "register {i} diverged after copy-prop cleanup for seeds {seeds:?}: \
                 original=0x{b:x} cleaned=0x{a:x}\nreport={:?}",
                outcome.report
            );
        }
    }
}

fn domain() -> Vec<Vec<(Reg, u64)>> {
    let samples: [u64; 6] = [0, 1, 7, 0x1234_5678, 0xFFFF_FFFF, 0x8000_0000];
    let mut out: Vec<Vec<(Reg, u64)>> = Vec::new();
    for &esi_v in &samples {
        for &edx_v in &samples {
            out.push(vec![(Reg::Rsi, esi_v), (Reg::Rdx, edx_v), (Reg::Rax, 0xAA)]);
        }
    }
    out
}

#[test]
fn junk_register_shuffle_round_trips_to_clean_form() {
    use iced_x86::Register;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.mov(ebx, ecx).unwrap();
    asm.mov(eax, ebx).unwrap();
    asm.add(eax, edx).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let live: [Register; 1] = [Register::EAX];
    let Some(outcome): Option<CopyPropOutcome> =
        clean_block_with_live_out(64, BASE, &body, Some(&live))
    else {
        panic!("clean_block_with_live_out returned None");
    };
    assert!(
        outcome.report.propagated_reads >= 1,
        "the eax<-ebx<-ecx<-esi copy chain must be propagated back to esi: {:?}",
        outcome.report
    );
    assert!(
        outcome.report.eliminated_dead_stores >= 1,
        "with only eax live at exit, the intermediate ecx/ebx junk copies are dead stores: {:?}",
        outcome.report
    );
    assert!(
        outcome.cleaned.len() < 4,
        "the cleaned block must be shorter than the 4-instruction junk shuffle: {:?}",
        outcome.report
    );

    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    for s in &seeds {
        let before: [u64; 16] = run_to_halt(&body, s.as_slice());
        let after: [u64; 16] = run_to_halt(&cleaned, s.as_slice());
        assert_eq!(
            before[0], after[0],
            "the live eax result (esi+edx) must survive copy-prop + dead-store cleanup; seeds {s:?}"
        );
    }
}

#[test]
fn redundant_self_move_is_dropped() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, esi).unwrap();
    asm.mov(eax, eax).unwrap();
    asm.add(eax, edx).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("simplifies");
    assert!(
        outcome.report.eliminated_copies >= 1,
        "the mov eax,eax no-op must be removed: {:?}",
        outcome.report
    );
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    let refs: Vec<&[(Reg, u64)]> = seeds
        .iter()
        .map(|s: &Vec<(Reg, u64)>| s.as_slice())
        .collect();
    assert_observably_equivalent(&body, &refs);
}

#[test]
fn overwritten_immediate_load_is_dead() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, 0x4141_4141u32 as i32).unwrap();
    asm.mov(ecx, esi).unwrap();
    asm.add(ecx, edx).unwrap();
    asm.mov(eax, ecx).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("simplifies");
    assert!(
        outcome.report.eliminated_dead_stores >= 1,
        "the first mov ecx,imm is overwritten before any read and must die: {:?}",
        outcome.report
    );
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    let refs: Vec<&[(Reg, u64)]> = seeds
        .iter()
        .map(|s: &Vec<(Reg, u64)>| s.as_slice())
        .collect();
    assert_observably_equivalent(&body, &refs);
}

#[test]
fn live_store_used_later_is_never_removed() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.add(eax, ecx).unwrap();
    asm.add(eax, ecx).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("simplifies");
    assert_eq!(
        outcome.report.eliminated_dead_stores, 0,
        "ecx is read twice, so its defining store is live and must survive: {:?}",
        outcome.report
    );
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    let refs: Vec<&[(Reg, u64)]> = seeds
        .iter()
        .map(|s: &Vec<(Reg, u64)>| s.as_slice())
        .collect();
    assert_observably_equivalent(&body, &refs);
}

#[test]
fn copy_through_a_clobbered_source_is_not_propagated() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.add(esi, edx).unwrap();
    asm.mov(eax, ecx).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("simplifies");
    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    for s in &seeds {
        let before: [u64; 16] = run_to_halt(&body, s.as_slice());
        let after: [u64; 16] = run_to_halt(&cleaned, s.as_slice());
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            if i == 4 {
                continue;
            }
            assert_eq!(
                b, a,
                "rax must still equal the ORIGINAL esi (captured into ecx before esi was \
                 clobbered), not the post-add esi: reg {i} 0x{b:x} vs 0x{a:x}"
            );
        }
    }
}

#[test]
fn block_with_memory_traffic_is_left_alone() {
    use iced_x86::code_asm::{dword_ptr, rbp};
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(dword_ptr(rbp - 4), esi).unwrap();
    asm.mov(eax, dword_ptr(rbp - 4)).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("decodes");
    assert_eq!(
        outcome.report.eliminated_dead_stores, 0,
        "stores/loads touching memory must not be treated as dead register defs: {:?}",
        outcome.report
    );
    assert_eq!(
        outcome.report.eliminated_copies, 0,
        "no register-to-register no-op exists to drop: {:?}",
        outcome.report
    );
}

#[test]
fn flag_consuming_arith_does_not_propagate_into_dependent_carry() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(edi, esi).unwrap();
    asm.add(eax, edi).unwrap();
    asm.adc(r8d, edi).unwrap();
    let body: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let outcome: CopyPropOutcome = clean_block(64, BASE, &body).expect("simplifies");
    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    let seeds: Vec<Vec<(Reg, u64)>> = domain();
    for s in &seeds {
        let extended: Vec<(Reg, u64)> = s
            .iter()
            .copied()
            .chain([(Reg::R8, 0x55), (Reg::Rdi, 0x99)])
            .collect();
        let before: [u64; 16] = run_to_halt(&body, &extended);
        let after: [u64; 16] = run_to_halt(&cleaned, &extended);
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            if i == 4 {
                continue;
            }
            assert_eq!(
                b, a,
                "adc carry-dependent result diverged at reg {i}: 0x{b:x} vs 0x{a:x}"
            );
        }
    }
}

#[test]
fn empty_block_is_rejected_and_oversized_input_is_bounded() {
    assert!(clean_block(64, BASE, &[]).is_none());
    let huge: Vec<u8> = (0..(MAX_BLOCK_INSNS + 64)).flat_map(|_| [0x90u8]).collect();
    let outcome: CopyPropOutcome =
        clean_block(64, BASE, &huge).expect("a long nop run still decodes to a bounded block");
    assert!(
        outcome.report.original_insns as usize <= MAX_BLOCK_INSNS,
        "decode must be capped at the instruction budget: {:?}",
        outcome.report
    );
}
