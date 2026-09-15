#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::identity_op,
    clippy::manual_is_multiple_of,
    clippy::too_many_lines,
    clippy::needless_type_cast
)]

use disrobe_pass_mobile::{
    DecompileReport, DisassemblyReport, Error, HERMES_LIFTED_VERSIONS, HERMES_MAGIC_LE_BYTES,
    HERMES_MAX_VERSION, HERMES_MIN_VERSION, HermesHeader, HermesModule, JsLiftReport,
    decompile_hermes_module, disassemble_hermes, header_size_for_version,
    hermes_lift_to_js_surface, parse_hermes_header, parse_hermes_module,
};

fn synth(version: u32) -> Vec<u8> {
    let identifiers: &[&str] = &["entry", "render", "update"];
    let strings: &[&str] = &["mount", "div"];
    let all: Vec<&str> = identifiers.iter().chain(strings.iter()).copied().collect();
    let mut storage: Vec<u8> = Vec::new();
    let mut offs: Vec<(u32, u32)> = Vec::new();
    for s in &all {
        let o: u32 = storage.len() as u32;
        let l: u32 = s.len() as u32;
        storage.extend_from_slice(s.as_bytes());
        offs.push((o, l));
    }
    let function_count: u32 = 1;
    let string_kind_count: u32 = 2;
    let identifier_count: u32 = identifiers.len() as u32;
    let string_count: u32 = all.len() as u32;
    let overflow_string_count: u32 = 0;
    let string_storage_size: u32 = storage.len() as u32;
    let header_size: usize = header_size_for_version(version);
    let mut buf: Vec<u8> = Vec::with_capacity(header_size + 4096);
    buf.extend_from_slice(&HERMES_MAGIC_LE_BYTES);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&function_count.to_le_bytes());
    buf.extend_from_slice(&string_kind_count.to_le_bytes());
    buf.extend_from_slice(&identifier_count.to_le_bytes());
    buf.extend_from_slice(&string_count.to_le_bytes());
    buf.extend_from_slice(&overflow_string_count.to_le_bytes());
    buf.extend_from_slice(&string_storage_size.to_le_bytes());
    if version >= 87 {
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    for _ in 0..7 {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    if version >= 84 {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.push(0u8);
    while buf.len() < header_size {
        buf.push(0u8);
    }
    let word0: u32 = 1u32 << 25;
    let word1: u32 = 1u32 << 15;
    let word2: u32 = 2u32 << 25;
    let word3: u32 = 0u32;
    buf.extend_from_slice(&word0.to_le_bytes());
    buf.extend_from_slice(&word1.to_le_bytes());
    buf.extend_from_slice(&word2.to_le_bytes());
    buf.extend_from_slice(&word3.to_le_bytes());
    while buf.len() % 4 != 0 {
        buf.push(0u8);
    }
    let id_kind: u32 = (1u32 << 31) | (identifier_count & 0x7fff_ffff);
    let str_kind: u32 = (string_count - identifier_count) & 0x7fff_ffff;
    buf.extend_from_slice(&id_kind.to_le_bytes());
    buf.extend_from_slice(&str_kind.to_le_bytes());
    while buf.len() % 4 != 0 {
        buf.push(0u8);
    }
    for _ in 0..identifier_count {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    while buf.len() % 4 != 0 {
        buf.push(0u8);
    }
    for (off, len) in &offs {
        let length_bits: u32 = (*len) & 0xff;
        let offset_bits: u32 = (*off) & 0x007f_ffff;
        let word: u32 = (offset_bits << 1) | (length_bits << 24);
        buf.extend_from_slice(&word.to_le_bytes());
    }
    while buf.len() % 4 != 0 {
        buf.push(0u8);
    }
    buf.extend_from_slice(&storage);
    while buf.len() % 4 != 0 {
        buf.push(0u8);
    }
    let file_len: u32 = buf.len() as u32;
    buf[32..36].copy_from_slice(&file_len.to_le_bytes());
    buf
}

#[test]
fn parse_header_matches_synth_v90() {
    let bytes: Vec<u8> = synth(90);
    let header: HermesHeader = parse_hermes_header(&bytes).expect("parse header");
    assert_eq!(header.version, 90);
    assert_eq!(header.function_count, 1);
}

#[test]
fn the_layout_probe_reads_every_version_the_reader_accepts() {
    let mut probed: u32 = 0;
    for version in HERMES_MIN_VERSION..=HERMES_MAX_VERSION {
        let bytes: Vec<u8> = synth(version);
        let module: HermesModule = parse_hermes_module(&bytes)
            .unwrap_or_else(|error: Error| panic!("v{version} is accepted by the reader: {error}"));
        assert_eq!(module.header.version, version);
        assert_eq!(module.functions.len(), 1, "v{version}");
        assert_eq!(module.identifiers.len(), 3, "v{version}");
        assert_eq!(module.strings.len(), 2, "v{version}");
        assert_eq!(
            module.header.debug_info_offset, 0,
            "v{version}: this probe is the only place a header declaring no debug info section is \
             read, so the field must stay zero here"
        );
        let report: DecompileReport = decompile_hermes_module(&module);
        assert_eq!(
            report.lift_supported,
            HERMES_LIFTED_VERSIONS.contains(&version),
            "v{version}: only the versions in {HERMES_LIFTED_VERSIONS:?} carry an opcode table, so \
             every other version must refuse a body rather than emit one nothing grades"
        );
        probed = probed.saturating_add(1);
    }
    assert_eq!(
        probed,
        HERMES_MAX_VERSION - HERMES_MIN_VERSION + 1,
        "every version the reader accepts is read here, because a version accepted and never read \
         is a layout nothing exercises"
    );
}

#[test]
fn a_version_outside_the_accepted_band_is_refused_by_number() {
    for version in [HERMES_MIN_VERSION - 1, HERMES_MAX_VERSION + 1] {
        let bytes: Vec<u8> = synth(version);
        let error: Error = parse_hermes_module(&bytes)
            .err()
            .unwrap_or_else(|| panic!("v{version} is outside the accepted band"));
        assert!(
            matches!(error, Error::HermesUnsupportedVersion(reported) if reported == version),
            "v{version} must be refused by number; got {error:?}"
        );
    }
}

#[test]
fn disassemble_resolves_function_name() {
    let bytes: Vec<u8> = synth(90);
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse");
    let report: DisassemblyReport = disassemble_hermes(&module);
    assert_eq!(report.function_count, 1);
    assert_eq!(report.functions[0].function_name, "render");
}

#[test]
fn lift_to_js_surface_emits_function_string() {
    let bytes: Vec<u8> = synth(90);
    let module: HermesModule = parse_hermes_module(&bytes).expect("parse");
    let lift: JsLiftReport = hermes_lift_to_js_surface(&module);
    assert_eq!(lift.function_surface.len(), 1);
    assert!(lift.function_surface[0].contains("function render"));
}
