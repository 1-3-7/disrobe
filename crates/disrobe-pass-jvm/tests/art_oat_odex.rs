#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    DexOptHeader, Error, InstructionSet, OatFile, OatHeader, OdexFile, ResourceTable, parse_arsc,
    parse_oat, parse_oat_header, parse_odex, parse_odex_header,
};

fn build_oat_header_bytes(dex_count: u32, iset: i32) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"oat\n");
    b.extend_from_slice(b"183\0");
    b.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    b.extend_from_slice(&iset.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&dex_count.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let kv: &[u8] = b"compiler-filter\0speed\0";
    b.extend_from_slice(&(kv.len() as u32).to_le_bytes());
    b.extend_from_slice(kv);
    b
}

fn build_oat_elf(rodata: &[u8], with_oatdata: bool) -> Vec<u8> {
    use object::write::{Object, StandardSection, Symbol, SymbolFlags, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolKind, SymbolScope};
    let mut obj: Object<'_> =
        Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let sec: object::write::SectionId = obj.section_id(StandardSection::ReadOnlyData);
    let off: u64 = obj.append_section_data(sec, rodata, 16);
    if with_oatdata {
        obj.add_symbol(Symbol {
            name: b"oatdata".to_vec(),
            value: off,
            size: rodata.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(sec),
            flags: SymbolFlags::None,
        });
    }
    obj.write().expect("elf write")
}

fn build_min_dex() -> Vec<u8> {
    let mut b: Vec<u8> = vec![0u8; 0x70];
    b[..4].copy_from_slice(b"dex\n");
    b[4..8].copy_from_slice(b"035\0");
    b[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    b
}

fn build_odex(inner_dex: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(b"dey\n036\0");
    let dex_off: u32 = 40;
    b.extend_from_slice(&dex_off.to_le_bytes());
    b.extend_from_slice(&(inner_dex.len() as u32).to_le_bytes());
    for _ in 0..6 {
        b.extend_from_slice(&0u32.to_le_bytes());
    }
    b.resize(dex_off as usize, 0);
    b.extend_from_slice(inner_dex);
    b
}

fn build_string_pool_utf8(strings: &[&str]) -> Vec<u8> {
    let header_size: u16 = 28;
    let string_count: u32 = strings.len() as u32;
    let mut offsets: Vec<u32> = Vec::with_capacity(strings.len());
    let mut data: Vec<u8> = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let bytes: &[u8] = s.as_bytes();
        data.push(bytes.len() as u8);
        data.push(bytes.len() as u8);
        data.extend_from_slice(bytes);
        data.push(0);
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let index_size: u32 = string_count * 4;
    let strings_start: u32 = u32::from(header_size) + index_size;
    let total: u32 = strings_start + data.len() as u32;

    let mut out: Vec<u8> = Vec::with_capacity(total as usize);
    out.extend_from_slice(&0x0001u16.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&string_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0x0000_0100u32.to_le_bytes());
    out.extend_from_slice(&strings_start.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

fn build_arsc() -> Vec<u8> {
    let global_pool: Vec<u8> = build_string_pool_utf8(&["app_name"]);
    let type_pool: Vec<u8> = build_string_pool_utf8(&["string"]);
    let key_pool: Vec<u8> = build_string_pool_utf8(&["app_name"]);

    let pkg_header_size: u32 = 12 + 256 + 4 + 4 + 4 + 4;
    let type_strings_off: u32 = pkg_header_size;
    let key_strings_off: u32 = type_strings_off + type_pool.len() as u32;
    let pkg_size: u32 = key_strings_off + key_pool.len() as u32;

    let mut package: Vec<u8> = Vec::new();
    package.extend_from_slice(&0x0200u16.to_le_bytes());
    package.extend_from_slice(&(pkg_header_size as u16).to_le_bytes());
    package.extend_from_slice(&pkg_size.to_le_bytes());
    package.extend_from_slice(&0x7fu32.to_le_bytes());
    let name: &str = "com.example";
    for ch in name.encode_utf16() {
        package.extend_from_slice(&ch.to_le_bytes());
    }
    let written_units: usize = name.encode_utf16().count();
    for _ in written_units..128 {
        package.extend_from_slice(&0u16.to_le_bytes());
    }
    package.extend_from_slice(&type_strings_off.to_le_bytes());
    package.extend_from_slice(&0u32.to_le_bytes());
    package.extend_from_slice(&key_strings_off.to_le_bytes());
    package.extend_from_slice(&0u32.to_le_bytes());
    package.extend_from_slice(&type_pool);
    package.extend_from_slice(&key_pool);

    let table_header_size: u16 = 12;
    let total_size: u32 =
        u32::from(table_header_size) + global_pool.len() as u32 + package.len() as u32;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&0x0002u16.to_le_bytes());
    out.extend_from_slice(&table_header_size.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&global_pool);
    out.extend_from_slice(&package);
    out
}

#[test]
fn oat_header_decodes_real_fields() {
    let rod: Vec<u8> = build_oat_header_bytes(3, 2);
    let h: OatHeader = parse_oat_header(&rod).expect("oat header");
    assert_eq!(h.dex_file_count, 3);
    assert_eq!(h.instruction_set, InstructionSet::Arm64);
    assert_eq!(h.version.digits(), 183);
    assert!(
        h.key_value_store
            .iter()
            .any(|(k, _): &(String, String)| k == "compiler-filter")
    );
}

#[test]
fn oat_via_elf_oatdata_symbol() {
    let elf: Vec<u8> = build_oat_elf(&build_oat_header_bytes(2, 2), true);
    let oat: OatFile = parse_oat(&elf).expect("oat from elf");
    assert_eq!(oat.header.dex_file_count, 2);
    assert_eq!(oat.instruction_set, InstructionSet::Arm64);
}

#[test]
fn odex_decodes_and_inner_dex_parses() {
    let odex: OdexFile = parse_odex(&build_odex(&build_min_dex())).expect("odex");
    assert_eq!(odex.header.version, *b"036\0");
    assert_eq!(odex.header.dex_offset, 40);
}

#[test]
fn odex_header_fields() {
    let h: DexOptHeader = parse_odex_header(&build_odex(&build_min_dex())).expect("odex header");
    assert_eq!(h.dex_length as usize, build_min_dex().len());
}

#[test]
fn arsc_decodes_table_pool_and_package() {
    let t: ResourceTable = parse_arsc(&build_arsc()).expect("arsc");
    assert_eq!(t.package_count, 1);
    assert!(!t.global_strings.strings.is_empty());
    assert_eq!(t.global_strings.strings[0], "app_name");
    assert_eq!(t.packages.len(), 1);
    assert_eq!(t.packages[0].id, 0x7f);
    assert_eq!(t.packages[0].name, "com.example");
}

#[test]
fn oat_rejects_bad_magic() {
    let err: Error = parse_oat_header(&[0u8; 32]).expect_err("bad oat magic");
    assert!(matches!(err, Error::BadOatMagic(_)));
}

#[test]
fn odex_rejects_bad_magic() {
    let err: Error = parse_odex_header(&[0u8; 40]).expect_err("bad odex magic");
    assert!(matches!(err, Error::BadOdexMagic(_)));
}

#[test]
fn arsc_rejects_wrong_top_chunk() {
    let bytes: [u8; 8] = [0xFF, 0x00, 12, 0, 8, 0, 0, 0];
    let err: Error = parse_arsc(&bytes).expect_err("bad arsc chunk");
    assert!(matches!(err, Error::BadArscChunk(_)));
}

#[test]
fn arsc_rejects_truncated() {
    let err: Error = parse_arsc(&[0x02u8, 0x00]).expect_err("truncated");
    assert!(matches!(
        err,
        Error::ArscTruncated { .. } | Error::Truncated { .. }
    ));
}

#[test]
fn oat_elf_without_oatdata_falls_through() {
    let plain_elf: Vec<u8> = build_oat_elf(b"not an oat region at all, just rodata", false);
    let err: Error = parse_oat(&plain_elf).expect_err("no oat anchor");
    assert!(matches!(err, Error::OatOffsetOutOfRange { .. }));
}
