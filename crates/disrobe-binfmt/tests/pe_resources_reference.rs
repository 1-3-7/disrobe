#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_binfmt::pe_resources::{
    ResourceEntry, ResourceId, ResourceReport, StringTable, pe_resources, resource_data,
};
use serde_json::Value;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/native/resources")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn reference() -> Value {
    serde_json::from_slice(&fixture("reference.json")).expect("reference JSON")
}

fn id_value(id: &ResourceId) -> Value {
    match id {
        ResourceId::Id(number) => Value::from(*number),
        ResourceId::Name(name) => Value::from(name.clone()),
    }
}

fn mismatches(report: &ResourceReport, reference: &Value) -> Vec<String> {
    let mut wrong: Vec<String> = Vec::new();
    let mut got: Vec<Value> = report
        .entries
        .iter()
        .map(|entry: &ResourceEntry| {
            serde_json::json!({
                "type": id_value(&entry.kind),
                "name": id_value(&entry.name),
                "language": entry.language,
                "size": entry.size,
                "sha256": entry.sha256,
            })
        })
        .collect();
    let mut expected: Vec<Value> = reference["tree"].as_array().expect("tree").clone();
    let key = |value: &Value| value.to_string();
    got.sort_by_key(key);
    expected.sort_by_key(key);
    if got != expected {
        wrong.push(format!("resource tree: {got:#?} != {expected:#?}"));
    }

    let version: &Value = &reference["version"];
    match &report.version {
        None => wrong.push("no version info".to_owned()),
        Some(info) => {
            let got_version: Value = serde_json::json!({
                "file_version": info.file_version,
                "product_version": info.product_version,
                "flags_mask": info.flags_mask,
                "flags": info.flags,
                "os": info.os,
                "type": info.file_type,
                "subtype": info.file_subtype,
                "translations": info.translations.iter().map(|(language, codepage)| serde_json::json!([language, codepage])).collect::<Vec<Value>>(),
                "strings": info.strings,
            });
            if &got_version != version {
                wrong.push(format!("version info: {got_version:#} != {version:#}"));
            }
        }
    }

    let tables: BTreeMap<u16, &StringTable> = report
        .string_tables
        .iter()
        .map(|table: &StringTable| (table.language, table))
        .collect();
    for (language, strings) in reference["strings"].as_object().expect("strings") {
        let language: u16 = language.parse().expect("language id");
        for (id, text) in strings.as_object().expect("table") {
            let id: u32 = id.parse().expect("string id");
            let block_present: bool = tables.get(&language).is_some_and(|table| {
                table
                    .strings
                    .keys()
                    .any(|other: &u32| other / 16 == id / 16)
            });
            let source: u16 = if block_present { language } else { 1033 };
            let got_text: Option<&String> =
                tables.get(&source).and_then(|table| table.strings.get(&id));
            if got_text.map(String::as_str) != text.as_str() {
                wrong.push(format!(
                    "string {id} for language {language}: {got_text:?} != {text}"
                ));
            }
        }
    }
    wrong
}

#[test]
fn resources_match_what_windows_reads_from_the_same_image() {
    let report: ResourceReport = pe_resources(&fixture("resources.exe")).expect("resources");
    let wrong: Vec<String> = mismatches(&report, &reference());
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    let manifest = report.manifests.first().expect("manifest");
    assert_eq!(
        manifest.execution_level.as_deref(),
        Some("requireAdministrator")
    );
    assert_eq!(manifest.ui_access, Some(false));
    assert_eq!(
        manifest.assembly_name.as_deref(),
        Some("Disrobe.ResourceSample")
    );
    assert_eq!(manifest.dpi_aware.as_deref(), Some("true/pm"));
    assert_eq!(
        manifest.dependencies,
        vec!["Microsoft.Windows.Common-Controls".to_owned()]
    );

    let icons = report.icon_groups.first().expect("icon group");
    let sizes: Vec<(u16, u16, u16)> = icons
        .images
        .iter()
        .map(|image| (image.width, image.height, image.bit_count))
        .collect();
    assert_eq!(sizes, vec![(16, 16, 32), (32, 32, 32)]);

    let payload: &ResourceEntry = report
        .entries
        .iter()
        .find(|entry| entry.name == ResourceId::Name("PAYLOAD".to_owned()))
        .expect("payload");
    assert_eq!(payload.content, Some("pe"));
    let source: Vec<u8> = fixture("src/payload.bin");
    assert_eq!(
        resource_data(&fixture("resources.exe"), payload),
        Some(source.as_slice())
    );
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    let at: usize = bytes
        .windows(from.len())
        .position(|window: &[u8]| window == from)
        .expect("pattern present");
    bytes[at..at + to.len()].copy_from_slice(to);
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn changed_resource_bytes_are_caught_by_the_grader() {
    let reference: Value = reference();
    for (what, from, to) in [
        (
            "version string",
            utf16("Disrobe Samples"),
            utf16("Disrobe Sampler"),
        ),
        ("string table", utf16("string forty"), utf16("string fifty")),
        (
            "payload",
            b"embedded payload marker".to_vec(),
            b"embedded payload mARKER".to_vec(),
        ),
    ] {
        let mut bytes: Vec<u8> = fixture("resources.exe");
        replace_once(&mut bytes, &from, &to);
        let report: ResourceReport = pe_resources(&bytes).expect("still parses");
        assert!(
            !mismatches(&report, &reference).is_empty(),
            "a changed {what} must not pass the grader"
        );
    }
}

#[test]
fn corrupted_images_give_a_report_or_an_error() {
    let original: Vec<u8> = fixture("resources.exe");
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for round in 0..400 {
        let mut bytes: Vec<u8> = original.clone();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for flip in 0..=(state % 8) {
            let at: usize = ((state >> (flip * 3)) % bytes.len() as u64) as usize;
            bytes[at] = (state >> (flip % 8 * 8)) as u8;
        }
        if round % 7 == 0 {
            bytes.truncate((state % bytes.len() as u64) as usize);
        }
        if let Ok(report) = pe_resources(&bytes) {
            for entry in &report.entries {
                let _ = resource_data(&bytes, entry);
            }
        }
    }
}
