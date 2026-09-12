use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, ebx, ecx, edx};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use super::*;
use crate::stub_emu::cpu::{NoopHost, map_buffer};
use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

const BASE: u64 = 0x4000;
const STACK_TOP: u64 = 0x2_0FF0;

fn decode(bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        out.push(insn);
    }
    out
}

fn nth_conditional_target(bytes: &[u8], occurrence: usize) -> u64 {
    decode(bytes)
        .into_iter()
        .filter(|i: &Instruction| i.flow_control() == FlowControl::ConditionalBranch)
        .nth(occurrence)
        .map(|i: Instruction| i.near_branch_target())
        .expect("nth conditional branch present")
}

fn concretely_reached_ips(bytes: &[u8], eax_value: u64) -> std::collections::BTreeSet<u64> {
    concretely_reached_ips_with_regs(bytes, &[(Reg::Rax, eax_value)])
}

fn concretely_reached_ips_with_regs(
    bytes: &[u8],
    values: &[(Reg, u64)],
) -> std::collections::BTreeSet<u64> {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    map_buffer(&mut cpu.mem, BASE, bytes, Perm::RX).expect("map code");
    cpu.mem.map(0x2_0000, 0x1000, Perm::RW).expect("map stack");
    cpu.regs.set(Reg::Rsp, STACK_TOP);
    for entry in values {
        let (reg, value): (Reg, u64) = *entry;
        cpu.regs.set(reg, value);
    }
    cpu.regs.rip = BASE;
    let mut host: NoopHost = NoopHost;
    let mut reached: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for _ in 0..256u32 {
        let ip: u64 = cpu.regs.rip;
        reached.insert(ip);
        if !cpu.mem.is_mapped(ip) {
            break;
        }
        let exit: crate::stub_emu::ExitReason = cpu.run(&mut host, 1).expect("single step");
        if matches!(
            exit,
            crate::stub_emu::ExitReason::JumpedOutOfRange { .. }
                | crate::stub_emu::ExitReason::UnsupportedInstr { .. }
                | crate::stub_emu::ExitReason::GuestFault(_)
                | crate::stub_emu::ExitReason::HostHalt(_)
        ) {
            break;
        }
        if cpu.regs.rip == ip {
            break;
        }
    }
    reached
}

fn four_var_correlated_program() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut out: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, ebx).unwrap();
    asm.jne(out).unwrap();
    asm.cmp(ecx, edx).unwrap();
    asm.jne(out).unwrap();
    asm.cmp(eax, ebx).unwrap();
    asm.jne(dead).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.mov(ecx, 99i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut out).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    asm.assemble(BASE).expect("assemble program")
}

fn correlated_signed_program() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut after: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, 5i32).unwrap();
    asm.jg(after).unwrap();
    asm.cmp(eax, 10i32).unwrap();
    asm.jg(dead).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.mov(ecx, 99i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut after).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    asm.assemble(BASE).expect("assemble program")
}

#[test]
fn correlated_branch_dead_edge_is_proven_unreachable() {
    let bytes: Vec<u8> = correlated_signed_program();
    let dead_target: u64 = nth_conditional_target(&bytes, 1);

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(
        report
            .dead_edges
            .iter()
            .any(|e: &DeadEdge| e.dead_target == dead_target && e.edge_taken),
        "the second branch taken-edge (eax > 10 given eax <= 5) must be proven infeasible; got {:?}",
        report.dead_edges
    );
}

#[test]
fn concrete_oracle_never_reaches_the_proven_dead_block() {
    let bytes: Vec<u8> = correlated_signed_program();
    let dead_target: u64 = nth_conditional_target(&bytes, 1);

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    let proven_dead: bool = report
        .dead_edges
        .iter()
        .any(|e: &DeadEdge| e.dead_target == dead_target && e.edge_taken);
    assert!(proven_dead, "symbolic engine must mark the edge dead first");

    for eax_value in 0..=40_000u64 {
        let reached: std::collections::BTreeSet<u64> = concretely_reached_ips(&bytes, eax_value);
        assert!(
            !reached.contains(&dead_target),
            "concrete emulation reached the supposedly-dead block at {dead_target:#x} for eax={eax_value}",
        );
    }

    let high: std::collections::BTreeSet<u64> = concretely_reached_ips(&bytes, 0xFFFF_FFFF);
    assert!(
        !high.contains(&dead_target),
        "even the maximal 32-bit eax must not reach the dead block, since the signed compare keeps eax<=5",
    );
}

#[test]
fn genuinely_reachable_branch_is_not_marked_dead() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut small: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, 100i32).unwrap();
    asm.jb(small).unwrap();
    asm.mov(ecx, 7i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut small).unwrap();
    asm.mov(ecx, 8i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(
        report.dead_edges.is_empty(),
        "a lone data-dependent branch has no dead edge; got {:?}",
        report.dead_edges
    );

    let small_target: u64 = nth_conditional_target(&bytes, 0);
    let reached_small: bool =
        (0..200u64).any(|v: u64| concretely_reached_ips(&bytes, v).contains(&small_target));
    let reached_fallthrough: bool =
        (0..400u64).any(|v: u64| !concretely_reached_ips(&bytes, v).contains(&small_target));
    assert!(
        reached_small && reached_fallthrough,
        "both edges of eax<100 are concretely reachable, so neither may be folded",
    );
}

#[test]
fn equal_constant_correlation_kills_inequality_edge() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut not_seven: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, 7i32).unwrap();
    asm.jne(not_seven).unwrap();
    asm.cmp(eax, 8i32).unwrap();
    asm.je(dead).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.mov(ecx, 99i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut not_seven).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let dead_target: u64 = nth_conditional_target(&bytes, 1);

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(
        report
            .dead_edges
            .iter()
            .any(|e: &DeadEdge| e.dead_target == dead_target && e.edge_taken),
        "after eax==7 is forced, eax==8 cannot hold; that je edge is dead; got {:?}",
        report.dead_edges
    );

    for eax_value in 0..=1000u64 {
        assert!(
            !concretely_reached_ips(&bytes, eax_value).contains(&dead_target),
            "concrete run reached the dead eax==8 block at eax={eax_value}",
        );
    }
}

#[test]
fn single_branch_has_no_correlation_and_no_dead_edge() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut taken: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, 3i32).unwrap();
    asm.jg(taken).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut taken).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(report.dead_edges.is_empty());
}

#[test]
fn entry_not_in_listing_yields_empty_report() {
    let bytes: Vec<u8> = correlated_signed_program();
    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE + 0xFFFF);
    assert!(report.dead_edges.is_empty());
    assert!(report.walls.is_empty());
}

#[test]
fn test_masked_low_bit_correlation_is_path_sensitive() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut odd: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.test(eax, 1i32).unwrap();
    asm.jne(odd).unwrap();
    asm.cmp(eax, 7i32).unwrap();
    asm.je(dead).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.mov(ecx, 99i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut odd).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.jmp(end).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let dead_target: u64 = nth_conditional_target(&bytes, 1);

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(
        report
            .dead_edges
            .iter()
            .any(|e: &DeadEdge| e.dead_target == dead_target && e.edge_taken),
        "fallthrough of test eax,1/jne forces eax even, so eax==7 is impossible; got {:?}",
        report.dead_edges
    );

    for eax_value in 0..=2000u64 {
        assert!(
            !concretely_reached_ips(&bytes, eax_value).contains(&dead_target),
            "even eax can never equal 7; concrete run reached dead block at eax={eax_value}",
        );
    }
}

#[test]
fn four_var_correlation_uses_bdd_solver_instead_of_wall() {
    let bytes: Vec<u8> = four_var_correlated_program();
    let dead_target: u64 = nth_conditional_target(&bytes, 2);

    let report: PathSenseReport = analyze(64, BASE, &bytes, BASE);
    assert!(
        report.walls.is_empty(),
        "four-register correlation must be solver-proven, not reported as a wall: {:?}",
        report.walls
    );
    assert!(
        report
            .dead_edges
            .iter()
            .any(|e: &DeadEdge| e.dead_target == dead_target && e.edge_taken),
        "after eax==ebx is forced, eax!=ebx is impossible even with ecx/edx also live; got {:?}",
        report.dead_edges
    );

    for eax_value in 0..=5u64 {
        for ebx_value in 0..=5u64 {
            for ecx_value in 0..=3u64 {
                for edx_value in 0..=3u64 {
                    let reached: std::collections::BTreeSet<u64> = concretely_reached_ips_with_regs(
                        &bytes,
                        &[
                            (Reg::Rax, eax_value),
                            (Reg::Rbx, ebx_value),
                            (Reg::Rcx, ecx_value),
                            (Reg::Rdx, edx_value),
                        ],
                    );
                    assert!(
                        !reached.contains(&dead_target),
                        "concrete run reached the solver-dead block for eax={eax_value} ebx={ebx_value} ecx={ecx_value} edx={edx_value}",
                    );
                }
            }
        }
    }
}
