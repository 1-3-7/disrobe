use iced_x86::code_asm::{CodeAssembler, dword_ptr, ecx, qword_ptr, rax, rcx};
use iced_x86::{Decoder, DecoderOptions, Instruction};

use super::*;
use crate::stub_emu::cpu::{ExitReason, NoopHost};
use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

const IMAGE_BASE: u64 = 0x40_0000;
const IMAGE_SIZE: u64 = 0x4000;
const DISPATCH_VA: u64 = 0x40_1000;
const TABLE_VA: u64 = 0x40_2000;
const CASE_VA: u64 = 0x40_1100;
const CASE_STRIDE: u64 = 0x40;
const STEP_CAP: u64 = 4096;

struct Layout {
    image: Vec<u8>,
    dispatch_block: Vec<u8>,
    case_count: u64,
}

fn place(image: &mut Vec<u8>, va: u64, bytes: &[u8]) {
    let offset: usize = (va - IMAGE_BASE) as usize;
    if image.len() < offset + bytes.len() {
        image.resize(offset + bytes.len(), 0xCC);
    }
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn case_va(index: u64) -> u64 {
    CASE_VA + index * CASE_STRIDE
}

fn assemble_at(va: u64, build: impl FnOnce(&mut CodeAssembler)) -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    build(&mut asm);
    asm.assemble(va).expect("assemble")
}

fn build_lea_register_layout(case_count: u64) -> Layout {
    let mut image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];

    let mut table: Vec<u8> = Vec::with_capacity(case_count as usize * 8);
    for index in 0..case_count {
        table.extend_from_slice(&case_va(index).to_le_bytes());
    }
    place(&mut image, TABLE_VA, &table);

    for index in 0..case_count {
        let stub: Vec<u8> = assemble_at(case_va(index), |asm: &mut CodeAssembler| {
            asm.mov(rcx, index).expect("marker");
            asm.int3().expect("halt");
        });
        place(&mut image, case_va(index), &stub);
    }

    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.lea(rax, qword_ptr(TABLE_VA)).expect("lea table");
        asm.jmp(qword_ptr(rax + rcx * 8)).expect("indirect jmp");
    });
    place(&mut image, DISPATCH_VA, &dispatch);

    Layout {
        image,
        dispatch_block: dispatch,
        case_count,
    }
}

fn reached_target_and_marker(image: &[u8], index: u64) -> (u64, u64) {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem
        .map(IMAGE_BASE, IMAGE_SIZE, Perm::RX)
        .expect("map image");
    cpu.mem.write_unchecked(IMAGE_BASE, image);
    cpu.regs.set(Reg::Rcx, index);
    cpu.regs.rip = DISPATCH_VA;
    let mut host: NoopHost = NoopHost;
    let _ = cpu.run(&mut host, STEP_CAP).expect("run dispatch");
    (cpu.regs.rip, cpu.regs.get(Reg::Rcx))
}

#[test]
fn resolves_lea_register_table_matching_emulation() {
    let layout: Layout = build_lea_register_layout(4);
    let resolution: JumpTableResolution = resolve_block(
        64,
        DISPATCH_VA,
        &layout.dispatch_block,
        IMAGE_BASE,
        &layout.image,
    )
    .expect("table resolves");

    assert_eq!(resolution.base_form, TableBaseForm::LeaRegister);
    assert_eq!(resolution.entry_scale, 8);
    assert_eq!(resolution.table_base, TABLE_VA);
    assert_eq!(resolution.cases.len(), layout.case_count as usize);

    for case in &resolution.cases {
        let (rip, marker): (u64, u64) = reached_target_and_marker(&layout.image, case.index);
        assert_eq!(
            case.target,
            case_va(case.index),
            "static target for index {} must equal the real case stub",
            case.index
        );
        assert_eq!(
            marker, case.index,
            "emulated dispatch for index {} must land on the matching case",
            case.index
        );
        assert!(
            rip >= case.target && rip < case.target + CASE_STRIDE,
            "emulated rip {rip:#x} must rest inside the statically-resolved case {:#x}",
            case.target
        );
    }
}

#[test]
fn resolves_memory_displacement_table_matching_emulation() {
    let case_count: u64 = 3;
    let mut image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];
    let mut table: Vec<u8> = Vec::new();
    for index in 0..case_count {
        table.extend_from_slice(&case_va(index).to_le_bytes());
    }
    place(&mut image, TABLE_VA, &table);
    for index in 0..case_count {
        let stub: Vec<u8> = assemble_at(case_va(index), |asm: &mut CodeAssembler| {
            asm.mov(rcx, index).expect("marker");
            asm.int3().expect("halt");
        });
        place(&mut image, case_va(index), &stub);
    }
    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.jmp(qword_ptr(TABLE_VA + rcx * 8)).expect("rip-rel jmp");
    });
    place(&mut image, DISPATCH_VA, &dispatch);

    let resolution: JumpTableResolution =
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).expect("table resolves");
    assert!(matches!(
        resolution.base_form,
        TableBaseForm::RipRelative | TableBaseForm::MemoryDisplacement
    ));
    assert_eq!(resolution.cases.len(), case_count as usize);

    for case in &resolution.cases {
        let (_rip, marker): (u64, u64) = reached_target_and_marker(&image, case.index);
        assert_eq!(
            case.target,
            case_va(case.index),
            "static target for index {} must equal the real case stub",
            case.index
        );
        assert_eq!(
            marker, case.index,
            "emulated indirect dispatch for index {} must land on the matching case",
            case.index
        );
    }
}

#[test]
fn does_not_resolve_when_index_register_is_not_table_indexed() {
    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.jmp(rax).expect("register-indirect jmp");
    });
    let image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];
    assert!(
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).is_none(),
        "a plain `jmp rax` is not a table dispatch and must not be resolved"
    );
}

#[test]
fn does_not_resolve_when_table_entries_point_outside_image() {
    let mut image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];
    let bogus: [u64; 4] = [0x9999_9999_9999, 0x8888_8888_8888, 0, 0];
    let mut table: Vec<u8> = Vec::new();
    for value in bogus {
        table.extend_from_slice(&value.to_le_bytes());
    }
    place(&mut image, TABLE_VA, &table);
    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.lea(rax, qword_ptr(TABLE_VA)).expect("lea");
        asm.jmp(qword_ptr(rax + rcx * 8)).expect("jmp");
    });
    place(&mut image, DISPATCH_VA, &dispatch);

    assert!(
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).is_none(),
        "entries pointing outside the image must not be accepted as real targets"
    );
}

fn decode(block: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, block, DISPATCH_VA, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[test]
fn clobbered_table_base_register_blocks_resolution() {
    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.lea(rax, qword_ptr(TABLE_VA)).expect("lea");
        asm.xor(rax, rax).expect("clobber base");
        asm.jmp(qword_ptr(rax + rcx * 8)).expect("jmp");
    });
    let image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];
    let insns: Vec<Instruction> = decode(&dispatch);
    assert!(insns.len() >= 3, "expected lea/xor/jmp");
    assert!(
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).is_none(),
        "a base register overwritten between the lea and the jmp must not resolve to the stale table"
    );
}

const DEFAULT_VA: u64 = 0x40_1080;
const DEFAULT_MARKER: u64 = 0xDEAD;

fn run_from(image: &[u8], dispatch_va: u64, index: u64) -> (u64, u64) {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem
        .map(IMAGE_BASE, IMAGE_SIZE, Perm::RX)
        .expect("map image");
    cpu.mem.write_unchecked(IMAGE_BASE, image);
    cpu.regs.set(Reg::Rcx, index);
    cpu.regs.rip = dispatch_va;
    let mut host: NoopHost = NoopHost;
    let exit: ExitReason = cpu.run(&mut host, STEP_CAP).expect("run dispatch");
    let _ = exit;
    (cpu.regs.rip, cpu.regs.get(Reg::Rcx))
}

fn place_default(image: &mut Vec<u8>) {
    let stub: Vec<u8> = assemble_at(DEFAULT_VA, |asm: &mut CodeAssembler| {
        asm.mov(rcx, DEFAULT_MARKER).expect("default marker");
        asm.int3().expect("halt");
    });
    place(image, DEFAULT_VA, &stub);
}

fn build_bounded_dispatch(case_count: u64) -> Vec<u8> {
    assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.cmp(ecx, (case_count - 1) as u32).expect("cmp bound");
        asm.ja(DEFAULT_VA).expect("ja default");
        asm.lea(rax, qword_ptr(TABLE_VA)).expect("lea table");
        asm.jmp(qword_ptr(rax + rcx * 8)).expect("indirect jmp");
    })
}

#[test]
fn cmp_ja_bound_caps_table_read_and_out_of_range_hits_default() {
    let case_count: u64 = 3;
    let mut image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];

    let mut table: Vec<u8> = Vec::new();
    for index in 0..case_count {
        table.extend_from_slice(&case_va(index).to_le_bytes());
    }
    for _ in 0..4 {
        table.extend_from_slice(&CASE_VA.to_le_bytes());
    }
    place(&mut image, TABLE_VA, &table);

    for index in 0..case_count {
        let stub: Vec<u8> = assemble_at(case_va(index), |asm: &mut CodeAssembler| {
            asm.mov(rcx, index).expect("marker");
            asm.int3().expect("halt");
        });
        place(&mut image, case_va(index), &stub);
    }
    place_default(&mut image);

    let dispatch: Vec<u8> = build_bounded_dispatch(case_count);
    place(&mut image, DISPATCH_VA, &dispatch);

    let resolution: JumpTableResolution =
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).expect("table resolves");
    assert_eq!(
        resolution.cases.len(),
        case_count as usize,
        "cmp/ja bound must cap the table read at the real case count, not over-read the {} trailing decoy entries: {:?}",
        4,
        resolution.cases
    );

    for case in &resolution.cases {
        let (rip, marker): (u64, u64) = run_from(&image, DISPATCH_VA, case.index);
        assert_eq!(
            case.target,
            case_va(case.index),
            "in-range index {} static target must equal its case stub",
            case.index
        );
        assert_eq!(
            marker, case.index,
            "in-range index {} must emulate to its matching case",
            case.index
        );
        assert!(
            rip >= case.target && rip < case.target + CASE_STRIDE,
            "in-range rip {rip:#x} must rest inside case {:#x}",
            case.target
        );
    }

    let (_rip, marker): (u64, u64) = run_from(&image, DISPATCH_VA, case_count);
    assert_eq!(
        marker, DEFAULT_MARKER,
        "an out-of-range index (> bound) must emulate to the default block, not a resolved case"
    );
}

#[test]
fn pic_rel32_switch_resolves_and_matches_emulation() {
    let case_count: u64 = 4;
    let mut image: Vec<u8> = vec![0xCC; IMAGE_SIZE as usize];

    let mut table: Vec<u8> = Vec::new();
    for index in 0..case_count {
        let delta: i64 = case_va(index) as i64 - TABLE_VA as i64;
        let delta32: i32 = i32::try_from(delta).expect("delta fits i32");
        table.extend_from_slice(&delta32.to_le_bytes());
    }
    place(&mut image, TABLE_VA, &table);

    for index in 0..case_count {
        let stub: Vec<u8> = assemble_at(case_va(index), |asm: &mut CodeAssembler| {
            asm.mov(rcx, index).expect("marker");
            asm.int3().expect("halt");
        });
        place(&mut image, case_va(index), &stub);
    }

    let dispatch: Vec<u8> = assemble_at(DISPATCH_VA, |asm: &mut CodeAssembler| {
        asm.lea(rax, qword_ptr(TABLE_VA)).expect("lea table");
        asm.movsxd(rcx, dword_ptr(rax + rcx * 4)).expect("load i32");
        asm.add(rcx, rax).expect("table_base + delta");
        asm.jmp(rcx).expect("register-indirect jmp");
    });
    place(&mut image, DISPATCH_VA, &dispatch);

    let resolution: JumpTableResolution =
        resolve_block(64, DISPATCH_VA, &dispatch, IMAGE_BASE, &image).expect("pic table resolves");
    assert_eq!(
        resolution.entry_scale, 4,
        "PIC tables hold 4-byte rel32 deltas"
    );
    assert_eq!(resolution.cases.len(), case_count as usize);

    for case in &resolution.cases {
        assert_eq!(
            case.target,
            case_va(case.index),
            "PIC static target for index {} must equal table_base + sext32(delta)",
            case.index
        );
        let (rip, _marker): (u64, u64) = run_from(&image, DISPATCH_VA, case.index);
        assert!(
            rip >= case.target && rip < case.target + CASE_STRIDE,
            "emulated PIC dispatch index {} rip {rip:#x} must land in case {:#x}",
            case.index,
            case.target
        );
    }
}
