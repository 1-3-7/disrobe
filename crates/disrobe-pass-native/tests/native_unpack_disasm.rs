#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::doc_markdown
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{
    RebuildLayout, RebuiltImage, rebuild_passthrough, rebuild_unpacked_pe,
    unpack_aspack_phase2_emulated, unpack_kkrunchy_phase2_emulated, unpack_mew_rebuilt,
    unpack_pecompact_phase2_emulated,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use object::{Object, ObjectSection, SectionFlags};

const IMAGE_SCN_MEM_EXECUTE: u64 = 0x2000_0000;

fn corpus(family: &str, name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push(family);
    p.push(name);
    fs::read(&p).ok()
}

#[allow(clippy::suboptimal_flops)]
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u64; 256] = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len: f64 = bytes.len() as f64;
    let mut h: f64 = 0.0;
    for &c in &counts {
        if c > 0 {
            let p: f64 = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

fn valid_instruction_count(code: &[u8], base: u64) -> usize {
    let mut decoder: Decoder<'_> = Decoder::with_ip(32, code, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut valid: usize = 0;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if !insn.is_invalid() {
            valid += 1;
        }
    }
    valid
}

fn distinct_intra_call_targets(code: &[u8], base: u64) -> usize {
    let lo: u64 = base;
    let hi: u64 = base + code.len() as u64;
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for start in 0..code.len() {
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            32,
            &code[start..],
            base + start as u64,
            DecoderOptions::NONE,
        );
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if matches!(insn.mnemonic(), Mnemonic::Call)
            && matches!(insn.flow_control(), FlowControl::Call)
            && insn.is_call_near()
        {
            let target: u64 = insn.near_branch_target();
            if target >= lo && target < hi {
                targets.insert(target);
            }
        }
    }
    targets.len()
}

fn executable_section(pe: &[u8]) -> Option<(u64, Vec<u8>)> {
    let file: object::File<'_> = object::File::parse(pe).ok()?;
    for section in file.sections() {
        let executable: bool = match section.flags() {
            SectionFlags::Coff { characteristics } => {
                characteristics & IMAGE_SCN_MEM_EXECUTE as u32 != 0
            }
            _ => false,
        };
        if !executable {
            continue;
        }
        let Ok(data): Result<&[u8], _> = section.data() else {
            continue;
        };
        if !data.is_empty() {
            return Some((section.address(), data.to_vec()));
        }
    }
    None
}

fn assert_loadable(rebuilt: &[u8], label: &str) {
    object::File::parse(rebuilt)
        .unwrap_or_else(|e| panic!("{label}: rebuilt image must parse as a loadable PE: {e}"));
}

#[test]
fn aspack_rebuilt_section_is_decompressed_code() {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.aspack.exe"),
        ("AccessEnum", "AccessEnum.packed.aspack.exe"),
    ];
    let mut exercised: usize = 0;
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = corpus("aspack", packed_name) else {
            eprintln!("skip aspack {label}: {packed_name} missing");
            continue;
        };
        let out = unpack_aspack_phase2_emulated(&packed, None).expect("aspack phase2");
        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &out.recovered_memory_image, out.oep_estimate)
                .expect("aspack rebuild");
        assert_eq!(
            rebuilt.layout,
            RebuildLayout::MemoryImageOverlay,
            "aspack {label}: phase-2 image must drive the memory-image overlay rebuild",
        );
        assert_loadable(&rebuilt.bytes, &format!("aspack {label}"));
        assert_decompressed_overlay(label, "aspack", &packed, &rebuilt.bytes);
        exercised += 1;
    }
    assert!(exercised > 0, "no aspack fixtures were exercised");
}

#[test]
fn pecompact_rebuilt_section_is_decompressed_code() {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.pecompact.exe"),
        ("AccessEnum", "AccessEnum.packed.pecompact.exe"),
    ];
    let mut exercised: usize = 0;
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = corpus("pecompact", packed_name) else {
            eprintln!("skip pecompact {label}: {packed_name} missing");
            continue;
        };
        let out = unpack_pecompact_phase2_emulated(&packed, None).expect("pecompact phase2");
        let rebuilt: RebuiltImage =
            rebuild_unpacked_pe(&packed, &out.recovered_memory_image, out.oep_estimate)
                .expect("pecompact rebuild");
        assert_eq!(
            rebuilt.layout,
            RebuildLayout::MemoryImageOverlay,
            "pecompact {label}: phase-2 image must drive the memory-image overlay rebuild",
        );
        assert_loadable(&rebuilt.bytes, &format!("pecompact {label}"));
        assert_decompressed_overlay(label, "pecompact", &packed, &rebuilt.bytes);
        exercised += 1;
    }
    assert!(exercised > 0, "no pecompact fixtures were exercised");
}

fn assert_decompressed_overlay(label: &str, family: &str, packed: &[u8], rebuilt: &[u8]) {
    let (packed_base, packed_code): (u64, Vec<u8>) =
        executable_section(packed).expect("packed exec section");
    let (rebuilt_base, rebuilt_code): (u64, Vec<u8>) =
        executable_section(rebuilt).expect("rebuilt exec section");
    assert_eq!(
        packed_base, rebuilt_base,
        "{family} {label}: overlay must keep the executable section at its load RVA",
    );
    let packed_entropy: f64 = shannon_entropy(&packed_code);
    let rebuilt_entropy: f64 = shannon_entropy(&rebuilt_code);
    let packed_calls: usize = distinct_intra_call_targets(&packed_code, packed_base);
    let rebuilt_calls: usize = distinct_intra_call_targets(&rebuilt_code, rebuilt_base);
    println!(
        "{family} {label}: entropy {packed_entropy:.2} -> {rebuilt_entropy:.2}, intra-calls {packed_calls} -> {rebuilt_calls}",
    );
    assert!(
        packed_entropy > 7.5,
        "{family} {label}: packed exec section should be near-random (>7.5 bits); got {packed_entropy:.2}",
    );
    assert!(
        rebuilt_entropy < packed_entropy - 1.0,
        "{family} {label}: decompressed section entropy must fall well below the packed blob ({rebuilt_entropy:.2} vs {packed_entropy:.2})",
    );
    assert!(
        rebuilt_calls >= 40,
        "{family} {label}: a disassembler must resolve many intra-section call targets in the decompressed code; got {rebuilt_calls} (packed had {packed_calls})",
    );
    assert!(
        rebuilt_calls > packed_calls * 8 + 8,
        "{family} {label}: decompressed call density must dwarf the packed blob ({rebuilt_calls} vs {packed_calls})",
    );
}

#[test]
fn mew_rebuilt_section_is_decompressed_code() {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.mew.exe"),
        ("AccessEnum", "AccessEnum.packed.mew.exe"),
        ("Autologon", "Autologon.packed.mew.exe"),
    ];
    let mut exercised: usize = 0;
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = corpus("mew", packed_name) else {
            eprintln!("skip mew {label}: {packed_name} missing");
            continue;
        };
        let rebuilt = unpack_mew_rebuilt(&packed).expect("mew rebuild");
        let image: RebuiltImage =
            rebuild_passthrough(&rebuilt.file_image).expect("mew passthrough");
        assert_loadable(&image.bytes, &format!("mew {label}"));

        assert!(
            executable_section(&packed).is_none(),
            "mew {label}: the packed MEW image carries no analyzable executable section",
        );
        let (base, code): (u64, Vec<u8>) =
            executable_section(&image.bytes).expect("mew rebuilt exec section");
        let entropy: f64 = shannon_entropy(&code);
        let valid: usize = valid_instruction_count(&code, base);
        let calls: usize = distinct_intra_call_targets(&code, base);
        println!(
            "mew {label}: exec {} bytes, entropy {entropy:.2}, valid insns {valid}, intra-calls {calls}, oep RVA {:#x}",
            code.len(),
            rebuilt.original_entry_point_rva,
        );
        assert!(
            entropy < 6.0,
            "mew {label}: decompressed code entropy must be code-like (<6.0); got {entropy:.2}",
        );
        assert!(
            valid > 5_000,
            "mew {label}: a disassembler must decode thousands of instructions in the decompressed image; got {valid}",
        );
        assert!(
            calls >= 40,
            "mew {label}: decompressed image must expose many intra-section call targets; got {calls}",
        );
        let oep_rva: u64 = u64::from(rebuilt.original_entry_point_rva);
        let oep_va: u64 = u64::from(rebuilt.image_base) + oep_rva;
        assert!(
            (base..base + code.len() as u64).contains(&oep_va),
            "mew {label}: restored OEP (VA {oep_va:#x}) must land inside the recovered executable section [{base:#x}, {:#x})",
            base + code.len() as u64,
        );
        exercised += 1;
    }
    assert!(exercised > 0, "no mew fixtures were exercised");
}

#[test]
fn kkrunchy_classic_rebuilt_is_decompressed_program() {
    let Some(packed): Option<Vec<u8>> = corpus("kkrunchy", "hello.packed.kkrunchy_classic.exe")
    else {
        eprintln!("skip kkrunchy classic: fixture missing");
        return;
    };
    let out = unpack_kkrunchy_phase2_emulated(&packed).expect("kkrunchy phase2");
    assert!(
        out.recovered_file_image.starts_with(b"MZ"),
        "kkrunchy classic: phase-2 must rebuild an MZ/PE file image",
    );
    let image: RebuiltImage =
        rebuild_passthrough(&out.recovered_file_image).expect("kkrunchy passthrough");
    assert_loadable(&image.bytes, "kkrunchy classic");

    let (packed_base, packed_code): (u64, Vec<u8>) =
        executable_section(&packed).expect("packed kkrunchy exec section");
    let (base, code): (u64, Vec<u8>) =
        executable_section(&image.bytes).expect("kkrunchy rebuilt exec section");
    let packed_entropy: f64 = shannon_entropy(&packed_code);
    let rebuilt_entropy: f64 = shannon_entropy(&code);
    let valid: usize = valid_instruction_count(&code, base);
    let packed_valid: usize = valid_instruction_count(&packed_code, packed_base);
    println!(
        "kkrunchy classic: entropy {packed_entropy:.2} -> {rebuilt_entropy:.2}, valid insns {packed_valid} -> {valid}",
    );
    assert!(
        rebuilt_entropy < packed_entropy - 1.0,
        "kkrunchy classic: decompressed .text entropy must fall below the compressed stub ({rebuilt_entropy:.2} vs {packed_entropy:.2})",
    );
    assert!(
        valid >= packed_valid,
        "kkrunchy classic: the decompressed program must decode to at least as many instructions as the packed stub ({valid} vs {packed_valid})",
    );
    assert!(
        valid > 50,
        "kkrunchy classic: the recovered program must contain real decoded instructions; got {valid}",
    );
}
