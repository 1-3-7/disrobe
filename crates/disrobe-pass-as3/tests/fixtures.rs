#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::path::{Path, PathBuf};

use disrobe_pass_as3::abc::{ABC_MAJOR, ABC_MINOR};
use disrobe_pass_as3::swf::{
    Swf, SwfCompression, SymbolClassEntry, TagCode, parse, parse_define_sprite, parse_do_abc,
    parse_symbol_class,
};
use disrobe_pass_as3::{DetectedLanguage, DetectionReport, detect_source_or_binary};

fn workspace_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn committed_fixture(relative: &str) -> Vec<u8> {
    let path: PathBuf = workspace_file(relative);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is a committed toolchain-produced fixture, so a run that cannot read it must \
             fail rather than grade nothing: {error}",
            path.display()
        )
    });
    assert!(!bytes.is_empty(), "{} is empty", path.display());
    bytes
}

fn rect_zero_bytes() -> Vec<u8> {
    vec![0x00]
}

fn pack_short_tag(code: u16, payload: &[u8]) -> Vec<u8> {
    let len: u16 = payload.len() as u16;
    let header: u16 = (code << 6) | (len & 0x3F);
    let mut out: Vec<u8> = Vec::new();
    if payload.len() < 0x3F {
        out.extend_from_slice(&header.to_le_bytes());
    } else {
        let long_header: u16 = (code << 6) | 0x3F;
        out.extend_from_slice(&long_header.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn build_swf(body_inner: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&rect_zero_bytes());
    body.extend_from_slice(&24_u16.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(body_inner);
    body.extend_from_slice(&pack_short_tag(TagCode::END.0, &[]));

    let mut swf: Vec<u8> = Vec::new();
    swf.extend_from_slice(b"FWS");
    swf.push(10);
    let file_length: u32 = (8 + body.len()) as u32;
    swf.extend_from_slice(&file_length.to_le_bytes());
    swf.extend_from_slice(&body);
    swf
}

#[test]
fn fixture_a_swf_with_define_sprite() {
    let sprite_payload: Vec<u8> = {
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&42_u16.to_le_bytes());
        p.extend_from_slice(&3_u16.to_le_bytes());
        p.extend_from_slice(&pack_short_tag(TagCode::SHOW_FRAME.0, &[]));
        p.extend_from_slice(&pack_short_tag(TagCode::END.0, &[]));
        p
    };
    let body_inner: Vec<u8> = pack_short_tag(TagCode::DEFINE_SPRITE.0, &sprite_payload);
    let bytes: Vec<u8> = build_swf(&body_inner);
    let swf: Swf = parse(&bytes).expect("parse FWS swf");
    assert_eq!(swf.header.compression, SwfCompression::None);
    assert_eq!(swf.header.frame_count, 1);

    let sprite_tag: &disrobe_pass_as3::SwfTag = swf
        .tags
        .iter()
        .find(|t| t.code == TagCode::DEFINE_SPRITE)
        .expect("expected DefineSprite tag");
    let sprite: disrobe_pass_as3::DefineSprite =
        parse_define_sprite(sprite_tag).expect("parse sprite");
    assert_eq!(sprite.character_id, 42);
    assert_eq!(sprite.frame_count, 3);
    assert!(sprite.tags.iter().any(|t| t.code == TagCode::SHOW_FRAME));
}

fn exported_declarations(pcode: &str) -> Vec<String> {
    let mut declarations: Vec<String> = Vec::new();
    let mut awaiting: bool = false;
    for line in pcode.lines() {
        if line.starts_with("; script ") {
            awaiting = true;
            continue;
        }
        if !awaiting {
            continue;
        }
        let mut rest: &str = line.trim();
        for modifier in ["public ", "internal ", "final ", "dynamic "] {
            rest = rest.strip_prefix(modifier).unwrap_or(rest);
        }
        let Some(declared): Option<&str> = rest
            .strip_prefix("class ")
            .or_else(|| rest.strip_prefix("interface "))
        else {
            continue;
        };
        let name: &str = declared
            .split_whitespace()
            .next()
            .expect("an exported declaration names its type");
        declarations.push(name.to_owned());
        awaiting = false;
    }
    declarations
}

#[test]
fn fixture_b_real_haxe_swf_matches_the_independent_decompiler_export() {
    let bytes: Vec<u8> = committed_fixture("corpus/flash/avm2_disasm_oracle/control_shapes.swf");
    let source: String = String::from_utf8(committed_fixture(
        "corpus/flash/avm2_disasm_oracle/ControlShapes.hx",
    ))
    .expect("the committed Haxe source is UTF-8");
    let pcode: String = String::from_utf8(committed_fixture(
        "corpus/flash/avm2_disasm_oracle/control_shapes.pcode.txt",
    ))
    .expect("the committed JPEXS export is UTF-8");
    let declared_main: &str = source
        .lines()
        .find_map(|line: &str| line.strip_prefix("class "))
        .and_then(|rest: &str| rest.split_whitespace().next())
        .expect("the committed Haxe source declares its main class");
    let exported: Vec<String> = exported_declarations(&pcode);
    assert_eq!(
        exported.len(),
        pcode
            .lines()
            .filter(|line: &&str| line.starts_with("; script "))
            .count(),
        "every exported script must declare exactly one type: {exported:?}"
    );
    assert!(exported.iter().any(|name: &String| name == declared_main));

    let swf: Swf = parse(&bytes).expect("parse the real Haxe 4.3.7 SWF");
    assert_eq!(swf.header.compression, SwfCompression::Zlib);
    let do_abc_tag: &disrobe_pass_as3::SwfTag = swf
        .tags
        .iter()
        .find(|t| t.code == TagCode::DO_ABC)
        .expect("the Haxe SWF carries a DoABC tag");
    let blob: disrobe_pass_as3::DoAbc = parse_do_abc(do_abc_tag).expect("parse do_abc");
    let abc: disrobe_pass_as3::AbcFile =
        disrobe_pass_as3::abc::parse(&blob.abc_bytes).expect("parse abc");
    assert_eq!(abc.minor, ABC_MINOR);
    assert_eq!(abc.major, ABC_MAJOR);
    let recovered: Vec<String> = abc.class_names();
    assert_eq!(
        recovered.len(),
        exported.len(),
        "the ABC instance table must hold the types the independent export lists: recovered \
         {recovered:?}, exported {exported:?}"
    );
    for name in &exported {
        assert!(
            recovered
                .iter()
                .any(|qualified: &String| qualified.contains(name.as_str())),
            "the recovered instance table lacks {name}: {recovered:?}"
        );
    }

    let symbol_tag: &disrobe_pass_as3::SwfTag = swf
        .tags
        .iter()
        .find(|t| t.code == TagCode::SYMBOL_CLASS)
        .expect("the Haxe SWF binds its document class through SymbolClass");
    let symbols: Vec<SymbolClassEntry> = parse_symbol_class(symbol_tag).expect("parse SymbolClass");
    assert_eq!(symbols.len(), 1, "{symbols:?}");
    assert_eq!(symbols[0].character_id, 0, "{symbols:?}");
    assert!(
        exported.contains(&symbols[0].class_name),
        "the document class bound to character 0 must be a type the independent export lists: \
         {symbols:?}"
    );
}

#[test]
fn fixture_c_real_haxe_source_is_identified_by_its_suffix_only() {
    let source: Vec<u8> =
        committed_fixture("crates/disrobe-pass-scriptlang/tests/fixtures/Main.hx");
    let hinted: DetectionReport = detect_source_or_binary(&source, Some("Main.hx"));
    assert!(hinted.detected.contains(&DetectedLanguage::Haxe));
    assert!(
        hinted
            .evidence
            .iter()
            .any(|line: &String| line == "filename suffix .hx")
    );
    let unhinted: DetectionReport = detect_source_or_binary(&source, None);
    assert!(
        !unhinted.detected.contains(&DetectedLanguage::Haxe),
        "real Haxe source without a haxe namespace reference carries no content signal: {unhinted:?}"
    );
}

#[test]
fn fixture_d_real_byteloader_bytecode_detected() {
    let bytes: Vec<u8> = committed_fixture("corpus/scriptlang/perl/hello.plc");
    let report: DetectionReport = detect_source_or_binary(&bytes, None);
    assert!(
        report.detected.contains(&DetectedLanguage::PerlBytecode),
        "{report:?}"
    );
    assert!(
        report.detected.contains(&DetectedLanguage::Perl),
        "{report:?}"
    );
    let source: Vec<u8> = committed_fixture("corpus/scriptlang/perl/hello.pl");
    let source_report: DetectionReport = detect_source_or_binary(&source, None);
    assert!(
        !source_report
            .detected
            .contains(&DetectedLanguage::PerlBytecode),
        "the source script the bytecode was compiled from is not bytecode: {source_report:?}"
    );
}

#[test]
fn fixture_e_real_nim_binary_detected() {
    let bytes: Vec<u8> = committed_fixture("corpus/native/nim/hello.nim.elf");
    let report: DetectionReport = detect_source_or_binary(&bytes, None);
    assert!(
        report.detected.contains(&DetectedLanguage::Nim),
        "{report:?}"
    );
}
