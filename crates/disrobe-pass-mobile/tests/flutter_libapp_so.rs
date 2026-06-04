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
    DART_ISOLATE_DATA_SYMBOL, DART_VM_DATA_SYMBOL, DartAotDecompile, DartSnapshotHeader,
    DartSnapshotKind, FlutterObfuscationMap, LibAppLayout, decompile_dart_aot, parse_dart_snapshot,
    parse_flutter_obfuscation_map, parse_libapp_so,
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
    buf.extend_from_slice(&2u64.to_le_bytes());
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
    assert!(!layout.section_names.is_empty());
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
fn parse_dart_snapshot_header_round_trip() {
    let bytes: Vec<u8> = synth_dart_snapshot();
    let header: DartSnapshotHeader = parse_dart_snapshot(&bytes).expect("parse snapshot");
    assert_eq!(header.magic, DART_SNAPSHOT_MAGIC);
    assert_eq!(header.kind, DartSnapshotKind::FullAot);
    assert_eq!(header.version_hash, "abcdef0123456789abcdef0123456789");
    assert!(header.features.contains("product"));
}

#[test]
fn decompile_dart_aot_finds_readable_strings() {
    let bytes: Vec<u8> = synth_dart_snapshot();
    let report: DartAotDecompile = decompile_dart_aot(&bytes).expect("decompile");
    assert!(
        report
            .readable_strings
            .iter()
            .any(|s: &String| s.contains("MaterialApp"))
    );
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
