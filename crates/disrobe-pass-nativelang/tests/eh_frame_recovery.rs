#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_nativelang::{
    DwarfReport, FunctionOrigin, FunctionRecovery, NativeImage, NativeLang, RecoveredFunction,
    recover_dwarf, recover_functions,
};

fn stripped_fixture() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("eh_frame");
    p.push("nim.stripped.elf");
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing committed fixture {}", p.display()))
}

fn eh_frame_starts(rec: &FunctionRecovery) -> BTreeSet<u64> {
    rec.functions
        .iter()
        .filter(|f: &&RecoveredFunction| f.origin == FunctionOrigin::EhFrame)
        .map(|f: &RecoveredFunction| f.start)
        .collect()
}

fn recover(bytes: &[u8]) -> FunctionRecovery {
    let image: NativeImage<'_> = NativeImage::parse(bytes).expect("parse elf");
    let dwarf: DwarfReport = recover_dwarf(&image);
    recover_functions(&image, NativeLang::Nim, &dwarf)
}

fn section_file_range(bytes: &[u8], target: &str) -> Option<(usize, usize)> {
    if bytes.len() < 0x40 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let rd16 = |off: usize| -> u16 { u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) };
    let rd32 = |off: usize| -> u32 { u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) };
    let rd64 = |off: usize| -> u64 { u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) };
    let e_shoff: usize = usize::try_from(rd64(0x28)).ok()?;
    let e_shentsize: usize = rd16(0x3a) as usize;
    let e_shnum: usize = rd16(0x3c) as usize;
    let e_shstrndx: usize = rd16(0x3e) as usize;
    let sh = |i: usize| -> usize { e_shoff + i * e_shentsize };
    let shstr_off: usize = usize::try_from(rd64(sh(e_shstrndx) + 0x18)).ok()?;
    let cstr = |off: usize| -> String {
        let end: usize = bytes[off..]
            .iter()
            .position(|b: &u8| *b == 0)
            .map_or(bytes.len(), |p: usize| off + p);
        String::from_utf8_lossy(&bytes[off..end]).into_owned()
    };
    for i in 0..e_shnum {
        let name_idx: usize = rd32(sh(i)) as usize;
        if cstr(shstr_off + name_idx) != target {
            continue;
        }
        let off: usize = usize::try_from(rd64(sh(i) + 0x18)).ok()?;
        let size: usize = usize::try_from(rd64(sh(i) + 0x20)).ok()?;
        return Some((off, size));
    }
    None
}

#[test]
fn eh_frame_recovers_starts_from_stripped_nim_without_symbol_table() {
    let bytes: Vec<u8> = stripped_fixture();
    let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse stripped nim");
    assert!(
        !image.has_symbol_table(),
        "stripped fixture must expose no symbol table"
    );
    assert!(
        image.func_symbols.is_empty(),
        "stripped fixture must expose no STT_FUNC symbols"
    );

    let rec: FunctionRecovery = recover(&bytes);
    assert_eq!(
        rec.from_symbol_table, 0,
        "no symbol-table functions expected"
    );
    assert_eq!(rec.from_dwarf, 0, "no dwarf functions expected");
    assert!(
        rec.from_eh_frame >= 180,
        "eh_frame source recovered too few: {}",
        rec.from_eh_frame
    );

    let starts: BTreeSet<u64> = eh_frame_starts(&rec);
    assert_eq!(
        starts.len(),
        rec.from_eh_frame,
        "eh_frame-origin functions must equal the eh_frame count"
    );
    let text: &disrobe_pass_nativelang::Section<'_> = image.text_section().expect(".text present");
    let lo: u64 = text.address;
    let hi: u64 = lo + text.data.len() as u64;
    assert!(
        starts.iter().all(|s: &u64| *s >= lo && *s < hi),
        "every eh_frame start must fall inside .text"
    );
}

#[test]
fn eh_frame_starts_match_unstripped_stt_func_starts() {
    let Some(unstripped): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        eprintln!("SKIP: corpus nim fixture missing");
        return;
    };
    let truth_image: NativeImage<'_> =
        NativeImage::parse(&unstripped).expect("parse unstripped nim");
    let truth: BTreeSet<u64> = truth_image
        .func_symbols
        .iter()
        .map(|s: &disrobe_pass_nativelang::FuncSymbol| s.address)
        .collect();
    assert!(!truth.is_empty(), "unstripped fixture must carry STT_FUNC");

    let stripped: Vec<u8> = stripped_fixture();
    let recovered: BTreeSet<u64> = eh_frame_starts(&recover(&stripped));
    assert!(!recovered.is_empty(), "eh_frame recovery must be non-empty");

    let tp: usize = recovered
        .iter()
        .filter(|s: &&u64| truth.contains(s))
        .count();
    let precision: f64 = tp as f64 / recovered.len() as f64;
    let recall: f64 = tp as f64 / truth.len() as f64;
    eprintln!(
        "eh_frame precision={precision:.4} recall={recall:.4} tp={tp} recovered={} truth={}",
        recovered.len(),
        truth.len()
    );
    assert!(precision >= 0.98, "precision {precision:.4} too low");
    assert!(recall >= 0.90, "recall {recall:.4} too low");
}

#[test]
fn eh_frame_does_not_double_count_symbol_table_functions() {
    let Some(unstripped): Option<Vec<u8>> = common::fixture_or_skip(common::NIM_ELF) else {
        eprintln!("SKIP: corpus nim fixture missing");
        return;
    };
    let rec: FunctionRecovery = recover(&unstripped);
    assert!(
        rec.from_symbol_table > 100,
        "symbol table must dominate here"
    );
    assert_eq!(
        rec.from_eh_frame, 0,
        "eh_frame starts already covered by the symbol table must not re-add"
    );
    assert!(
        eh_frame_starts(&rec).is_empty(),
        "no eh_frame-origin duplicates when symbols cover every start"
    );
}

#[test]
fn eh_frame_recovery_collapses_when_section_zeroed() {
    let base: Vec<u8> = stripped_fixture();
    assert!(recover(&base).from_eh_frame >= 180);

    let (off, size): (usize, usize) =
        section_file_range(&base, ".eh_frame").expect(".eh_frame file range");
    let mut corrupted: Vec<u8> = base;
    for byte in &mut corrupted[off..off + size] {
        *byte = 0;
    }
    let after: FunctionRecovery = recover(&corrupted);
    assert!(
        after.from_eh_frame <= 2,
        "zeroing .eh_frame must starve the source, got {}",
        after.from_eh_frame
    );
}
