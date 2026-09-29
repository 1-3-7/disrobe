#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{Error, ResStringPool, ResourceTable, parse_arsc};

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const UTF8_FLAG: u32 = 0x0000_0100;

fn push_utf8_pool(strings: &[&str]) -> Vec<u8> {
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
    out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&string_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&UTF8_FLAG.to_le_bytes());
    out.extend_from_slice(&strings_start.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

fn build_arsc() -> Vec<u8> {
    let global_pool: Vec<u8> = push_utf8_pool(&["@string/x"]);
    let type_pool: Vec<u8> = push_utf8_pool(&["string"]);
    let key_pool: Vec<u8> = push_utf8_pool(&["app_name"]);

    let pkg_header_size: u32 = 12 + 256 + 4 + 4 + 4 + 4;
    let type_strings_off: u32 = pkg_header_size;
    let key_strings_off: u32 = type_strings_off + type_pool.len() as u32;
    let pkg_size: u32 = key_strings_off + key_pool.len() as u32;

    let mut package: Vec<u8> = Vec::new();
    package.extend_from_slice(&RES_TABLE_PACKAGE_TYPE.to_le_bytes());
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
    out.extend_from_slice(&RES_TABLE_TYPE.to_le_bytes());
    out.extend_from_slice(&table_header_size.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&global_pool);
    out.extend_from_slice(&package);
    out
}

#[test]
fn parses_minimal_resources_arsc() {
    let table: ResourceTable = parse_arsc(&build_arsc()).expect("minimal resources.arsc parses");
    assert_eq!(table.package_count, 1);
    assert_eq!(table.global_strings.strings, vec!["@string/x".to_owned()]);
    assert_eq!(table.packages.len(), 1);

    let pkg: &disrobe_pass_jvm::ResTablePackage = &table.packages[0];
    assert_eq!(pkg.id, 0x7f);
    assert_eq!(pkg.name, "com.example");
    assert_eq!(pkg.type_strings.strings, vec!["string".to_owned()]);
    assert_eq!(pkg.key_strings.strings, vec!["app_name".to_owned()]);

    let global: &ResStringPool = &table.global_strings;
    assert!(global.is_utf8);
}

#[test]
fn rejects_wrong_root_type() {
    let mut bytes: Vec<u8> = build_arsc();
    bytes[0] = 0x03;
    bytes[1] = 0x00;
    let err: Error = parse_arsc(&bytes).expect_err("wrong root chunk type");
    assert!(matches!(err, Error::BadArscChunk(0x0003)));
}

#[test]
fn rejects_truncated() {
    let full: Vec<u8> = build_arsc();
    let bytes: &[u8] = &full[..full.len() - 4];
    let err: Error = parse_arsc(bytes).expect_err("truncated body");
    assert!(matches!(
        err,
        Error::ArscTruncated { .. } | Error::Truncated { .. }
    ));
}
