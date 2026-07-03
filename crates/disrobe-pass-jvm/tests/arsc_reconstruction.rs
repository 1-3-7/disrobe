#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::{ResourceTable, parse_arsc};

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("apk");
    p.push(name);
    p
}

fn entry(apk: &[u8], name: &str) -> Vec<u8> {
    use std::io::{Cursor, Read};
    let cursor: Cursor<&[u8]> = Cursor::new(apk);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor).expect("zip open");
    let mut f: zip::read::ZipFile<'_> = zip.by_name(name).expect("entry present");
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf).expect("read entry");
    buf
}

fn fixture_table() -> ResourceTable {
    let apk: Vec<u8> = fs::read(corpus("fixture-v2v3-signed.apk")).expect("read fixture apk");
    let arsc: Vec<u8> = entry(&apk, "resources.arsc");
    parse_arsc(&arsc).expect("arsc parses")
}

#[test]
fn r_txt_lists_resource_with_full_id() {
    let table: ResourceTable = fixture_table();
    let r_txt: String = table.r_txt();
    assert_eq!(
        r_txt.trim(),
        "int string app_name 0x7f010000",
        "R.txt entry matches aapt2 R.txt format (type name 0xID)"
    );
}

#[test]
fn r_java_reconstructs_nested_class_constants() {
    let table: ResourceTable = fixture_table();
    let r_java: String = table.r_java("com.disrobe.fixture");
    assert!(
        r_java.contains("package com.disrobe.fixture;"),
        "package header present; got:\n{r_java}"
    );
    assert!(
        r_java.contains("public final class R {"),
        "R class declared; got:\n{r_java}"
    );
    assert!(
        r_java.contains("public static final class string {"),
        "nested type class; got:\n{r_java}"
    );
    assert!(
        r_java.contains("public static final int app_name = 0x7f010000;"),
        "constant matches the resource id; got:\n{r_java}"
    );
}

#[test]
fn values_xml_reconstructs_default_config() {
    let table: ResourceTable = fixture_table();
    let files: BTreeMap<String, String> = table.values_xml();
    let doc: &String = files
        .get("res/values/values.xml")
        .unwrap_or_else(|| panic!("default values.xml present; got keys {:?}", files.keys()));
    assert!(
        doc.contains("<resources>") && doc.contains("</resources>"),
        "values.xml is a resources document; got:\n{doc}"
    );
    assert!(
        doc.contains("<string name=\"app_name\">"),
        "app_name string reconstructed with resolved value; got:\n{doc}"
    );
}

const RES_TABLE_TYPE: u16 = 0x0002;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;

fn utf16_pool(strings: &[&str]) -> Vec<u8> {
    let mut offsets: Vec<u32> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let header: u16 = 28;
    let index_size: u32 = offsets.len() as u32 * 4;
    let strings_start: u32 = u32::from(header) + index_size;
    let size: u32 = strings_start + data.len() as u32;
    let mut pool: Vec<u8> = Vec::new();
    pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    pool.extend_from_slice(&header.to_le_bytes());
    pool.extend_from_slice(&size.to_le_bytes());
    pool.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in &offsets {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);
    pool
}

fn type_chunk_with_config(type_id: u8, config: &[u8], key: &str) -> Vec<u8> {
    let header_size: u16 = 20 + config.len() as u16;
    let entry_count: u32 = 1;
    let _ = key;
    let mut entry: Vec<u8> = Vec::new();
    entry.extend_from_slice(&8u16.to_le_bytes());
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes());
    entry.extend_from_slice(&8u16.to_le_bytes());
    entry.push(0);
    entry.push(0x10);
    entry.extend_from_slice(&42u32.to_le_bytes());

    let index_size: u32 = entry_count * 4;
    let entries_start: u32 = u32::from(header_size) + index_size;
    let size: u32 = entries_start + entry.len() as u32;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&RES_TABLE_TYPE_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.push(type_id);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entries_start.to_le_bytes());
    out.extend_from_slice(config);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&entry);
    out
}

fn config_bytes(fields: &[(usize, &[u8])]) -> Vec<u8> {
    let needed: usize = fields
        .iter()
        .map(|(off, bytes): &(usize, &[u8])| off + bytes.len())
        .max()
        .unwrap_or(0)
        .max(28);
    let mut len: usize = needed;
    while !len.is_multiple_of(4) {
        len += 1;
    }
    let mut c: Vec<u8> = vec![0u8; len];
    for (off, bytes) in fields {
        c[*off..*off + bytes.len()].copy_from_slice(bytes);
    }
    let size: u32 = c.len() as u32;
    c[0..4].copy_from_slice(&size.to_le_bytes());
    c
}

fn build_arsc_with_config(config: &[u8]) -> Vec<u8> {
    let global_pool: Vec<u8> = utf16_pool(&["value"]);
    let type_pool: Vec<u8> = utf16_pool(&["string"]);
    let key_pool: Vec<u8> = utf16_pool(&["item"]);
    let type_chunk: Vec<u8> = type_chunk_with_config(1, config, "item");

    let pkg_header_size: u16 = 12 + 256 + 4 + 4 + 4 + 4;
    let mut pkg_body: Vec<u8> = Vec::new();
    let type_strings_off: u32 = u32::from(pkg_header_size);
    let key_strings_off: u32 = type_strings_off + type_pool.len() as u32;
    pkg_body.extend_from_slice(&type_pool);
    pkg_body.extend_from_slice(&key_pool);
    pkg_body.extend_from_slice(&type_chunk);

    let pkg_size: u32 = u32::from(pkg_header_size) + pkg_body.len() as u32;
    let mut pkg: Vec<u8> = Vec::new();
    pkg.extend_from_slice(&RES_TABLE_PACKAGE_TYPE.to_le_bytes());
    pkg.extend_from_slice(&pkg_header_size.to_le_bytes());
    pkg.extend_from_slice(&pkg_size.to_le_bytes());
    pkg.extend_from_slice(&0x7fu32.to_le_bytes());
    let name_units: Vec<u16> = "x".encode_utf16().collect();
    for u in &name_units {
        pkg.extend_from_slice(&u.to_le_bytes());
    }
    for _ in 0..(128 - name_units.len()) {
        pkg.extend_from_slice(&0u16.to_le_bytes());
    }
    pkg.extend_from_slice(&type_strings_off.to_le_bytes());
    pkg.extend_from_slice(&0u32.to_le_bytes());
    pkg.extend_from_slice(&key_strings_off.to_le_bytes());
    pkg.extend_from_slice(&0u32.to_le_bytes());
    pkg.extend_from_slice(&pkg_body);

    let table_header: u16 = 12;
    let total: u32 = u32::from(table_header) + global_pool.len() as u32 + pkg.len() as u32;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&RES_TABLE_TYPE.to_le_bytes());
    out.extend_from_slice(&table_header.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&global_pool);
    out.extend_from_slice(&pkg);
    out
}

#[test]
fn config_qualifier_decodes_density_orientation_locale() {
    let config: Vec<u8> = config_bytes(&[
        (8, b"en"),
        (10, b"US"),
        (12, &[0x02]),
        (14, &480u16.to_le_bytes()),
    ]);
    let arsc: Vec<u8> = build_arsc_with_config(&config);
    let table: ResourceTable = parse_arsc(&arsc).expect("synthetic arsc parses");
    let pkg: &disrobe_pass_jvm::ResTablePackage = &table.packages[0];
    let qualifier: &str = pkg.types[0].qualifier.as_str();
    assert_eq!(
        qualifier, "en-rUS-land-xxhdpi",
        "full ResTable_config decode matches aapt2 qualifier order"
    );
}

#[test]
fn config_qualifier_decodes_smallest_width_and_sdk() {
    let config: Vec<u8> = config_bytes(&[(24, &21u16.to_le_bytes()), (30, &600u16.to_le_bytes())]);
    let arsc: Vec<u8> = build_arsc_with_config(&config);
    let table: ResourceTable = parse_arsc(&arsc).expect("synthetic arsc parses");
    let qualifier: &str = table.packages[0].types[0].qualifier.as_str();
    assert_eq!(
        qualifier, "sw600dp-v21",
        "smallestWidthDp and sdkVersion qualifiers decode"
    );
}
