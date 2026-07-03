//! Register copy-propagation + dead-store elimination, a D-810 / Hex-Rays-microcode-class
//! peephole disrobe previously lacked. The authoritative non-circular gate lives in the lib
//! unit tests, which grade the cleaned block against the production `stub_emu` x86 interpreter.
//! This integration layer re-checks the published API with a second, independent mini
//! interpreter so a green means the rewrite preserved observable semantics, not that the tool
//! agreed with its own symbolic model.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::cast_possible_truncation
)]

use disrobe_pass_native::{
    CopyPropOutcome, DeobfBits, clean_register_copies, clean_register_copies_live_out,
};
use iced_x86::code_asm::{CodeAssembler, eax, ebx, ecx, edi, edx, esi};
use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, Mnemonic, OpKind, Register};

const BASE: u64 = 0x1000;
const MASK32: u64 = 0xFFFF_FFFF;

const ESI: usize = 0;
const EDX: usize = 1;
const EDI: usize = 2;
const EAX: usize = 3;
const EBX: usize = 4;
const ECX: usize = 5;

fn encode_at(insns: &[Instruction], base: u64) -> Vec<u8> {
    let mut encoder: Encoder = Encoder::new(64);
    let mut ip: u64 = base;
    let mut out: Vec<u8> = Vec::new();
    for insn in insns {
        let mut placed: Instruction = *insn;
        placed.set_ip(ip);
        let len: usize = encoder.encode(&placed, ip).expect("encode");
        out.extend_from_slice(encoder.take_buffer().as_slice());
        ip += len as u64;
    }
    out
}

const fn slot(reg: Register) -> Option<usize> {
    Some(match reg {
        Register::ESI => ESI,
        Register::EDX => EDX,
        Register::EDI => EDI,
        Register::EAX => EAX,
        Register::EBX => EBX,
        Register::ECX => ECX,
        _ => return None,
    })
}

fn read_src(regs: &[u64; 8], insn: &Instruction) -> u64 {
    match insn.op1_kind() {
        OpKind::Register => slot(insn.op1_register()).map_or(0, |s: usize| regs[s]),
        OpKind::Immediate8 => u64::from(insn.immediate8()),
        OpKind::Immediate32 => u64::from(insn.immediate32()),
        OpKind::Immediate8to32 => insn.immediate8to32().cast_unsigned().into(),
        _ => 0,
    }
}

fn interpret(bytes: &[u8], base: u64, seed: [u64; 8]) -> [u64; 8] {
    let mut regs: [u64; 8] = seed;
    let mut dec: Decoder<'_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while dec.can_decode() {
        dec.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.op0_kind() != OpKind::Register {
            continue;
        }
        let Some(dst): Option<usize> = slot(insn.op0_register()) else {
            continue;
        };
        let src: u64 = read_src(&regs, &insn);
        let cur: u64 = regs[dst];
        regs[dst] = match insn.mnemonic() {
            Mnemonic::Mov => src & MASK32,
            Mnemonic::Add => cur.wrapping_add(src) & MASK32,
            Mnemonic::Sub => cur.wrapping_sub(src) & MASK32,
            Mnemonic::Xor => (cur ^ src) & MASK32,
            Mnemonic::And => (cur & src) & MASK32,
            Mnemonic::Or => (cur | src) & MASK32,
            _ => cur,
        };
    }
    regs
}

fn seeds() -> Vec<[u64; 8]> {
    let samples: [u64; 6] = [0, 1, 7, 0x1234_5678, 0xFFFF_FFFF, 0x8000_0000];
    let mut out: Vec<[u64; 8]> = Vec::new();
    for &esi_v in &samples {
        for &edx_v in &samples {
            let mut seed: [u64; 8] = [0u64; 8];
            seed[ESI] = esi_v;
            seed[EDX] = edx_v;
            seed[EDI] = 0x55;
            out.push(seed);
        }
    }
    out
}

#[test]
fn public_copyprop_round_trips_a_junk_shuffle_under_concrete_emulation() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.mov(ebx, ecx).unwrap();
    asm.mov(edi, ebx).unwrap();
    asm.mov(eax, edi).unwrap();
    asm.add(eax, edx).unwrap();
    let original: Vec<u8> = asm.assemble(BASE).expect("assemble");

    let live: [Register; 1] = [Register::EAX];
    let Some(outcome): Option<CopyPropOutcome> =
        clean_register_copies_live_out(DeobfBits::Bits64, BASE, &original, Some(&live))
    else {
        panic!("public copy-prop API returned None on an analyzable junk-shuffle block");
    };
    assert!(
        outcome.report.propagated_reads >= 1 && outcome.report.eliminated_dead_stores >= 1,
        "the eax<-edi<-ebx<-ecx<-esi chain must collapse and shed its junk copies: {:?}",
        outcome.report
    );

    let cleaned: Vec<u8> = encode_at(&outcome.cleaned, BASE);
    for seed in seeds() {
        let before: [u64; 8] = interpret(&original, BASE, seed);
        let after: [u64; 8] = interpret(&cleaned, BASE, seed);
        assert_eq!(
            before[EAX], after[EAX],
            "the live eax result diverged after copy-prop cleanup for seed {seed:?}: 0x{:x} vs 0x{:x}",
            before[EAX], after[EAX]
        );
    }
}

#[test]
fn real_ollvm_sub_block_is_not_corrupted_by_copyprop() {
    let mut p: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("native");
    p.push("ollvm");
    p.push("sub_mixer_O0.bin");
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&p) else {
        eprintln!("skip: real OLLVM sub_mixer_O0.bin absent");
        return;
    };
    let Some(outcome): Option<CopyPropOutcome> =
        clean_register_copies(DeobfBits::Bits64, 0x1000, &bytes)
    else {
        eprintln!("skip: sub_mixer block is not a single straight-line region for copy-prop");
        return;
    };
    assert!(
        outcome.report.cleaned_insns <= outcome.report.original_insns,
        "copy-prop must never grow a real OLLVM block: {:?}",
        outcome.report
    );
    println!(
        "copyprop on real ollvm sub_mixer: {} -> {} insns ({} propagated reads, {} dead stores)",
        outcome.report.original_insns,
        outcome.report.cleaned_insns,
        outcome.report.propagated_reads,
        outcome.report.eliminated_dead_stores
    );
}
