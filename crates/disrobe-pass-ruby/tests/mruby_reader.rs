#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};

mod common;

fn rite_with_irep_sections(
    format: [u8; 4],
    irep_count: usize,
    trailing_after_end: bool,
) -> Vec<u8> {
    let mut sections: Vec<Vec<u8>> = Vec::with_capacity(irep_count + 2);
    for _ in 0..irep_count {
        sections.push(common::synth_section(*b"IREP", &[0u8; 16]));
    }
    sections.push(common::synth_section(*b"END\0", &[]));
    if trailing_after_end {
        sections.push(common::synth_section(*b"IREP", &[0u8; 16]));
    }
    common::synth_rite(format, &sections)
}

#[test]
fn reader_counts_exactly_the_irep_sections_present() {
    for fmt in [*b"0001", *b"0002", *b"0003", *b"0030", *b"0200", *b"0300"] {
        for expected in [0usize, 1, 2, 3] {
            let bytes: Vec<u8> = rite_with_irep_sections(fmt, expected, false);
            let analysis: RubyAnalysis = analyze_bytes(&bytes, "tiny.mrb").expect("analyze");
            assert_eq!(analysis.flavor, Flavor::MrubyBinary);
            let mrb = analysis.mruby.expect("mruby");
            assert_eq!(
                mrb.binary.irep_count as usize, expected,
                "format {fmt:?} with {expected} IREP section(s) must count exactly {expected}"
            );
            assert_eq!(mrb.binary.sections.len(), expected + 1);
            assert!(!mrb.binary.has_debug);
        }
    }
}

#[test]
fn reader_stops_counting_at_the_end_section() {
    let bytes: Vec<u8> = rite_with_irep_sections(*b"0300", 2, true);
    let mrb = analyze_bytes(&bytes, "t.mrb")
        .expect("analyze")
        .mruby
        .expect("mruby");
    assert_eq!(
        mrb.binary.irep_count, 2,
        "an IREP section placed after END must not inflate the count"
    );
    assert_eq!(mrb.binary.sections.len(), 3);
}

#[test]
fn reader_flags_debug_and_lvar_sections_independently() {
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &[0u8; 16]),
        common::synth_section(*b"DBG\0", &[0u8; 4]),
        common::synth_section(*b"END\0", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let mrb = analyze_bytes(&bytes, "t.mrb")
        .expect("analyze")
        .mruby
        .expect("mruby");
    assert_eq!(mrb.binary.irep_count, 1);
    assert!(mrb.binary.has_debug, "DBG section must set has_debug");
    assert!(
        !mrb.binary.has_lvar,
        "no LVAR section means has_lvar stays false"
    );
}

#[test]
fn unknown_section_id_is_skipped_not_rejected() {
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"WUT?", &[0u8; 4]),
        common::synth_section(*b"IREP", &[0u8; 16]),
        common::synth_section(*b"END\0", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let mrb = analyze_bytes(&bytes, "x.mrb")
        .expect("an unknown section must be skipped, not fail the whole binary")
        .mruby
        .expect("mruby");
    assert_eq!(
        mrb.binary.irep_count, 1,
        "the IREP section after the unknown one must still be counted"
    );
    assert_eq!(
        mrb.binary.sections.len(),
        2,
        "the unknown section is skipped and not recorded"
    );
}

#[test]
fn real_rite0004_binary_parses_its_header_and_sections_through_the_crc_and_no_catch_field_branch() {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("ruby");
    path.push("mruby");
    path.push("legacy");
    path.push("greet_rite0004.mrb");
    let bytes: Vec<u8> =
        std::fs::read(&path).expect("committed real mruby 1.4.1 RITE0004 fixture present");
    assert_eq!(
        &bytes[4..8],
        b"0004",
        "fixture must carry format version 0004"
    );
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greet_rite0004.mrb").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::MrubyBinary);
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.binary.header.crc_present,
        "a real pre-mruby-2.0 header carries the two-byte CRC field this binary was built with"
    );
    assert_eq!(
        mrb.binary.irep_count, 1,
        "the section scan must land correctly on the real IREP and END sections after the \
         22-byte CRC-bearing header, not the 20-byte modern one"
    );
    assert!(
        mrb.binary.has_lvar,
        "the real mrbc 1.4.1 output carries a LVAR section this binary was built with"
    );
    assert!(
        mrb.irep.is_none(),
        "mruby switched its irep record body from a 32-bit packed mrb_code word to a byte-packed \
         encoding at mruby 2.0; a RITE0004 body predates that switch and this disassembler is \
         calibrated to the byte-packed encoding, so the irep body is honestly unparsed rather \
         than guessed at, even though the header and section framing now succeed"
    );
}
