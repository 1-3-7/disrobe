#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::identity_op,
    clippy::too_many_lines,
    clippy::needless_type_cast,
    clippy::missing_const_for_fn,
    clippy::too_many_arguments
)]

use disrobe_pass_mobile::DART_SNAPSHOT_MAGIC;
use disrobe_pass_mobile::{
    AotLiftReport, DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL, DART_VM_DATA_SYMBOL,
    DartAotDecompile, DartLiftedFunction, DartProgramSkeleton, DartRecoveryCounts,
    DartSnapshotHeader, DartSnapshotKind, DartStaticRecovery, Error, FlutterObfuscationMap,
    LibAppLayout, build_dart_program_skeleton, dart_recovery_counts, decompile_dart_aot,
    decompile_libapp_so_structured, lift_libapp_aot, parse_dart_snapshot,
    parse_flutter_obfuscation_map, parse_libapp_so, recover_dart_static,
};

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u16_at(bytes: &[u8], offset: usize) -> u16 {
    let end: usize = offset + 2;
    let raw: [u8; 2] = bytes[offset..end].try_into().expect("u16 bytes");
    u16::from_le_bytes(raw)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    let end: usize = offset + 4;
    let raw: [u8; 4] = bytes[offset..end].try_into().expect("u32 bytes");
    u32::from_le_bytes(raw)
}

fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
    let end: usize = offset + 8;
    let raw: [u8; 8] = bytes[offset..end].try_into().expect("u64 bytes");
    u64::from_le_bytes(raw)
}

fn forge_isolate_symbol_size(bytes: &mut [u8], size: u64) {
    let shoff: usize = usize::try_from(read_u64_at(bytes, 40)).expect("section header offset");
    let shentsize: usize = usize::from(read_u16_at(bytes, 58));
    let shnum: usize = usize::from(read_u16_at(bytes, 60));
    let mut symtab_offset: Option<usize> = None;
    for index in 0..shnum {
        let base: usize = shoff + index * shentsize;
        let sh_type: u32 = read_u32_at(bytes, base + 4);
        if sh_type == 2 {
            symtab_offset = Some(usize::try_from(read_u64_at(bytes, base + 24)).expect("symtab"));
            break;
        }
    }
    let symtab: usize = symtab_offset.expect("symtab section");
    let isolate_size_offset: usize = symtab + 2 * 24 + 16;
    bytes[isolate_size_offset..isolate_size_offset + 8].copy_from_slice(&size.to_le_bytes());
}

fn synth_minimal_libapp_so() -> Vec<u8> {
    let snapshot_payload: Vec<u8> = synth_dart_snapshot();
    let isolate_payload: Vec<u8> = snapshot_payload.clone();

    let mut shstrtab: Vec<u8> = Vec::new();
    shstrtab.push(0);
    let shstr_text_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let shstr_rodata_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".rodata\0");
    let shstr_shstrtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let shstr_symtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".symtab\0");
    let shstr_strtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".strtab\0");

    let mut strtab: Vec<u8> = Vec::new();
    strtab.push(0);
    let str_vm_data_off: u32 = strtab.len() as u32;
    strtab.extend_from_slice(DART_VM_DATA_SYMBOL.as_bytes());
    strtab.push(0);
    let str_isolate_data_off: u32 = strtab.len() as u32;
    strtab.extend_from_slice(DART_ISOLATE_DATA_SYMBOL.as_bytes());
    strtab.push(0);

    let elf_header_size: u64 = 64;
    let section_header_size: u64 = 64;
    let section_count: u64 = 6;

    let snapshot_addr: u64 = 0x1000;
    let isolate_addr: u64 = snapshot_addr + snapshot_payload.len() as u64;
    let snapshot_off: u64 = elf_header_size;
    let isolate_off: u64 = snapshot_off + snapshot_payload.len() as u64;
    let shstrtab_off: u64 = isolate_off + isolate_payload.len() as u64;
    let strtab_off: u64 = shstrtab_off + shstrtab.len() as u64;

    let sym_entry_size: u64 = 24;
    let sym_count: u64 = 3;
    let symtab_size: u64 = sym_count * sym_entry_size;
    let symtab_off: u64 = strtab_off + strtab.len() as u64;

    let section_headers_off: u64 = symtab_off + symtab_size;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf.push(2);
    buf.push(1);
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(&[0u8; 8]);
    write_u16(&mut buf, 3);
    write_u16(&mut buf, 0x3e);
    write_u32(&mut buf, 1);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, section_headers_off);
    write_u32(&mut buf, 0);
    write_u16(&mut buf, elf_header_size as u16);
    write_u16(&mut buf, 0);
    write_u16(&mut buf, 0);
    write_u16(&mut buf, section_header_size as u16);
    write_u16(&mut buf, section_count as u16);
    write_u16(&mut buf, 3);

    assert_eq!(buf.len(), 64);

    buf.extend_from_slice(&snapshot_payload);
    buf.extend_from_slice(&isolate_payload);
    buf.extend_from_slice(&shstrtab);
    buf.extend_from_slice(&strtab);

    write_sym_entry(&mut buf, 0, 0, 0, 0, 0, 0);
    write_sym_entry(
        &mut buf,
        str_vm_data_off,
        0x11,
        0,
        4,
        snapshot_addr,
        snapshot_payload.len() as u64,
    );
    write_sym_entry(
        &mut buf,
        str_isolate_data_off,
        0x11,
        0,
        4,
        isolate_addr,
        isolate_payload.len() as u64,
    );

    assert_eq!(buf.len() as u64, section_headers_off);

    write_section_header(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    write_section_header(
        &mut buf,
        shstr_text_off,
        1,
        0x6,
        snapshot_addr,
        snapshot_off,
        snapshot_payload.len() as u64,
        0,
        0,
        16,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_rodata_off,
        1,
        0x2,
        isolate_addr,
        isolate_off,
        isolate_payload.len() as u64,
        0,
        0,
        16,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_shstrtab_off,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_strtab_off,
        3,
        0,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_symtab_off,
        2,
        0,
        0,
        symtab_off,
        symtab_size,
        4,
        1,
        8,
        sym_entry_size,
    );

    buf
}

fn write_section_header(
    buf: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) {
    write_u32(buf, sh_name);
    write_u32(buf, sh_type);
    write_u64(buf, sh_flags);
    write_u64(buf, sh_addr);
    write_u64(buf, sh_offset);
    write_u64(buf, sh_size);
    write_u32(buf, sh_link);
    write_u32(buf, sh_info);
    write_u64(buf, sh_addralign);
    write_u64(buf, sh_entsize);
}

fn write_sym_entry(
    buf: &mut Vec<u8>,
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
) {
    write_u32(buf, st_name);
    buf.push(st_info);
    buf.push(st_other);
    write_u16(buf, st_shndx);
    write_u64(buf, st_value);
    write_u64(buf, st_size);
}

fn synth_dart_snapshot() -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&DART_SNAPSHOT_MAGIC.to_le_bytes());
    buf.extend_from_slice(&0x800u64.to_le_bytes());
    buf.extend_from_slice(&3u64.to_le_bytes());
    buf.extend_from_slice(b"abcdef0123456789abcdef0123456789");
    buf.extend_from_slice(b"product no-causal_async_stacks");
    buf.push(0u8);
    for i in 0..64u32 {
        buf.extend_from_slice(&i.to_le_bytes());
    }
    buf.extend_from_slice(b"\x00LibraryPrivate@MyApp\x00MaterialApp\x00");
    buf
}

#[test]
fn parse_libapp_so_finds_dart_snapshot_symbols() {
    let bytes: Vec<u8> = synth_minimal_libapp_so();
    let layout: LibAppLayout = parse_libapp_so(&bytes).expect("parse libapp.so");
    let vm: &disrobe_pass_mobile::SnapshotSection = layout
        .vm_snapshot_data
        .as_ref()
        .expect("vm snapshot symbol");
    assert_eq!(vm.symbol, DART_VM_DATA_SYMBOL);
    let iso: &disrobe_pass_mobile::SnapshotSection = layout
        .isolate_snapshot_data
        .as_ref()
        .expect("isolate snapshot symbol");
    assert_eq!(iso.symbol, DART_ISOLATE_DATA_SYMBOL);
    for expected in [".text", ".rodata", ".shstrtab", ".symtab", ".strtab"] {
        assert!(
            layout.section_names.iter().any(|n: &String| n == expected),
            "section-header string table must decode {expected}, got {:?}",
            layout.section_names
        );
    }
}

#[test]
fn parse_flutter_apk_extracts_and_parses_libapp() {
    use std::io::{Cursor, Write};

    use disrobe_pass_mobile::{FlutterApkLayout, parse_flutter_apk};
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let so: Vec<u8> = synth_minimal_libapp_so();
    let mut apk: Vec<u8> = Vec::new();
    {
        let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut apk);
        let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file::<&str, ()>("AndroidManifest.xml", opts)
            .unwrap();
        zw.write_all(b"<manifest/>").unwrap();
        zw.start_file::<&str, ()>("lib/arm64-v8a/libapp.so", opts)
            .unwrap();
        zw.write_all(&so).unwrap();
        zw.finish().unwrap();
    }
    let parsed: FlutterApkLayout = parse_flutter_apk(&apk).expect("parse flutter apk");
    assert_eq!(parsed.libapp_path, "lib/arm64-v8a/libapp.so");
    assert_eq!(parsed.libapp_size as usize, so.len());
    assert_eq!(
        parsed
            .layout
            .vm_snapshot_data
            .as_ref()
            .expect("vm data from apk")
            .symbol,
        DART_VM_DATA_SYMBOL
    );
}

#[test]
#[cfg(feature = "chain")]
fn malformed_snapshot_symbol_fails_mobile_pass_child_recovery() {
    use disrobe_core::chain::Pass as _;
    use disrobe_core::{Artifact, CoreError, Rung};
    use disrobe_pass_mobile::chain_detector::MOBILE_PASS;

    let mut bytes: Vec<u8> = synth_minimal_libapp_so();
    forge_isolate_symbol_size(&mut bytes, u64::MAX);

    let err: Error =
        decompile_libapp_so_structured(&bytes).expect_err("forged snapshot symbol size must fail");
    assert!(
        matches!(err, Error::DartSectionOutOfBounds { .. }),
        "expected snapshot section bounds error, got {err}"
    );

    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let pass_err: CoreError = MOBILE_PASS
        .run(&artifact)
        .expect_err("mobile pass must fail closed");
    let message: String = pass_err.to_string();
    assert!(
        message.contains("DR-MOB-0032"),
        "expected surfaced snapshot section error, got {message}"
    );
}

#[test]
fn parse_dart_snapshot_header_round_trip() {
    let bytes: Vec<u8> = synth_dart_snapshot();
    let header: DartSnapshotHeader = parse_dart_snapshot(&bytes).expect("parse snapshot");
    assert_eq!(header.magic, DART_SNAPSHOT_MAGIC);
    assert_eq!(header.kind, DartSnapshotKind::FullAot);
    assert_eq!(header.version_hash, "abcdef0123456789abcdef0123456789");
    assert!(header.features.contains("product"));
}

#[test]
fn decompile_dart_aot_string_scanner_extracts_planted_ascii_runs() {
    let bytes: Vec<u8> = synth_dart_snapshot();
    let report: DartAotDecompile = decompile_dart_aot(&bytes).expect("decompile");
    for planted in ["MaterialApp", "LibraryPrivate@MyApp"] {
        assert!(
            report
                .readable_strings
                .iter()
                .any(|s: &String| s.contains(planted)),
            "the null-delimited ascii string scanner must surface the planted run {planted:?}; \
             this is scanner mechanics on a hand-built snapshot blob, not app recovery, which is \
             graded against the real AOT in real_flutter_libapp_recovery.rs; got {:?}",
            report.readable_strings
        );
    }
}

#[test]
fn obfuscation_map_array_round_trip() {
    let json: &[u8] = br#"["MyHomePage","aA","incrementCounter","bB"]"#;
    let map: FlutterObfuscationMap = parse_flutter_obfuscation_map(json).expect("parse map");
    assert_eq!(map.entries, 2);
    assert_eq!(
        map.obfuscated_to_original.get("aA").map(String::as_str),
        Some("MyHomePage")
    );
}

const ARM64_PUSH_FP_LR: u32 = 0xA9BF_7BFD;
const ARM64_MOV_FP_SP: u32 = 0x9100_03FD;
const ARM64_RET: u32 = 0xD65F_03C0;
const IMAGE_HEADER_SIZE: usize = 64;

fn synth_dart_instructions(func_count: usize, arg_regs: u8) -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; IMAGE_HEADER_SIZE];
    for _ in 0..func_count {
        write_u32(&mut v, ARM64_PUSH_FP_LR);
        write_u32(&mut v, ARM64_MOV_FP_SP);
        for r in 0..arg_regs {
            write_u32(&mut v, 0x9100_0000 | ((r as u32) << 5));
        }
        write_u32(&mut v, ARM64_RET);
        while !v.len().is_multiple_of(16) {
            v.push(0u8);
        }
    }
    v
}

fn synth_dart_classifier_input() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for token in [
        "package:myapp/main.dart",
        "package:flutter/material.dart",
        "MyHomePage",
        "_MyHomePageState",
        "build",
        "createState",
        "get:length@1a2b3c",
        "incrementCounter",
    ] {
        v.push(0u8);
        v.extend_from_slice(token.as_bytes());
        v.push(0u8);
    }
    v
}

#[test]
fn arm64_boundary_scanner_counts_prologues() {
    let instructions: Vec<u8> = synth_dart_instructions(5, 3);
    let recovery: DartStaticRecovery = recover_dart_static(&[], &instructions);
    let skeleton: DartProgramSkeleton = build_dart_program_skeleton(&recovery);
    assert_eq!(
        skeleton.function_count, 5,
        "scanner must count the 5 planted ARM64 frame prologues"
    );
    for f in &skeleton.functions {
        assert!(
            f.body.contains("not decompiled to source"),
            "every body is the AOT machine-code marker, never reconstructed as source"
        );
    }
    let counts: DartRecoveryCounts = dart_recovery_counts(&skeleton);
    assert_eq!(counts.bodies_recovered, 0, "bodies are never recoverable");
}

#[test]
fn name_classifier_buckets_dart_identifiers() {
    let data: Vec<u8> = synth_dart_classifier_input();
    let recovery: DartStaticRecovery = recover_dart_static(&data, &[]);
    assert!(
        recovery
            .library_uris
            .iter()
            .any(|u: &String| u == "package:myapp/main.dart"),
        "library-uri bucket must catch package: prefixes"
    );
    assert!(
        recovery
            .class_names
            .iter()
            .any(|c: &String| c == "MyHomePage"),
        "class bucket must catch upper-camel identifiers"
    );
    assert!(
        recovery
            .method_names
            .iter()
            .any(|m| m.scrubbed == "build" || m.scrubbed == "createState"),
        "method bucket must catch lower-camel identifiers"
    );
    eprintln!(
        "classifier raw counts on synthetic input: classes={} methods={} libraries={} (mechanics test, NOT a recovery rate)",
        recovery.class_names.len(),
        recovery.method_names.len(),
        recovery.library_uris.len()
    );
}

fn synth_libapp_so_symbol_flood(text_len_bytes: usize, func_symbol_count: usize) -> Vec<u8> {
    let mut text: Vec<u8> = Vec::with_capacity(text_len_bytes);
    while text.len() < text_len_bytes {
        write_u32(&mut text, 0xd503_201f);
    }
    text.truncate(text_len_bytes);

    let mut shstrtab: Vec<u8> = Vec::new();
    shstrtab.push(0);
    let shstr_text_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let shstr_shstrtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let shstr_symtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".symtab\0");
    let shstr_strtab_off: u32 = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".strtab\0");

    let mut strtab: Vec<u8> = Vec::new();
    strtab.push(0);
    let str_instr_off: u32 = strtab.len() as u32;
    strtab.extend_from_slice(DART_ISOLATE_INSTR_SYMBOL.as_bytes());
    strtab.push(0);
    let str_func_off: u32 = strtab.len() as u32;
    strtab.extend_from_slice(b"A");
    strtab.push(0);

    let elf_header_size: u64 = 64;
    let section_header_size: u64 = 64;
    let section_count: u64 = 5;

    let text_addr: u64 = 0x1000;
    let text_off: u64 = elf_header_size;
    let shstrtab_off: u64 = text_off + text.len() as u64;
    let strtab_off: u64 = shstrtab_off + shstrtab.len() as u64;

    let sym_entry_size: u64 = 24;
    let sym_count: u64 = 2 + func_symbol_count as u64;
    let symtab_size: u64 = sym_count * sym_entry_size;
    let symtab_off: u64 = strtab_off + strtab.len() as u64;
    let section_headers_off: u64 = symtab_off + symtab_size;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf.push(2);
    buf.push(1);
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(&[0u8; 8]);
    write_u16(&mut buf, 3);
    write_u16(&mut buf, 0xb7);
    write_u32(&mut buf, 1);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, 0);
    write_u64(&mut buf, section_headers_off);
    write_u32(&mut buf, 0);
    write_u16(&mut buf, elf_header_size as u16);
    write_u16(&mut buf, 0);
    write_u16(&mut buf, 0);
    write_u16(&mut buf, section_header_size as u16);
    write_u16(&mut buf, section_count as u16);
    write_u16(&mut buf, 2);
    assert_eq!(buf.len(), 64);

    buf.extend_from_slice(&text);
    buf.extend_from_slice(&shstrtab);
    buf.extend_from_slice(&strtab);

    write_sym_entry(&mut buf, 0, 0, 0, 0, 0, 0);
    write_sym_entry(
        &mut buf,
        str_instr_off,
        0x11,
        0,
        1,
        text_addr,
        text.len() as u64,
    );
    let modulus: u64 = text.len().max(1) as u64;
    for i in 0..func_symbol_count {
        let value: u64 = text_addr + (i as u64 % modulus);
        write_sym_entry(&mut buf, str_func_off, 0x12, 0, 1, value, text.len() as u64);
    }
    assert_eq!(buf.len() as u64, section_headers_off);

    write_section_header(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    write_section_header(
        &mut buf,
        shstr_text_off,
        1,
        0x6,
        text_addr,
        text_off,
        text.len() as u64,
        0,
        0,
        16,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_shstrtab_off,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_section_header(
        &mut buf,
        shstr_symtab_off,
        2,
        0,
        0,
        symtab_off,
        symtab_size,
        4,
        1,
        8,
        sym_entry_size,
    );
    write_section_header(
        &mut buf,
        shstr_strtab_off,
        3,
        0,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    );

    buf
}

#[test]
fn lift_libapp_aot_bounds_overlapping_symbol_flood() {
    let text_len: usize = 4096;
    let flood: usize = 4000;
    let so: Vec<u8> = synth_libapp_so_symbol_flood(text_len, flood);
    let cap: usize = text_len / 4;

    let layout: LibAppLayout = parse_libapp_so(&so).expect("parse crafted libapp.so");
    assert!(
        layout.function_symbols.len() <= cap,
        "the function-symbol collector must cap a flood at one entry per instruction slot; got {} for a {text_len}-byte region",
        layout.function_symbols.len()
    );

    let report: AotLiftReport = lift_libapp_aot(&so).expect("lift crafted libapp.so");
    assert!(
        report.function_count <= cap,
        "the symtab disassembler must not emit more functions than instruction slots; got {}",
        report.function_count
    );
    let retained: usize = report
        .functions
        .iter()
        .map(|f: &DartLiftedFunction| f.instruction_count)
        .sum::<usize>();
    assert!(
        retained <= cap,
        "overlapping symbols must decode each region slot at most once; retained {retained} for a {text_len}-byte region"
    );
}
