#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::scratch::scratch_root;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_swift_objc::archive_pass::{APPLE_ARCHIVE_PASS, AppleArchiveDetector};
use disrobe_pass_swift_objc::nib_archive::{
    NibArchive, NibConnection, NibValue, decode_nib_archive,
};
use serde_json::Value;

const LOCAL_PREREQUISITE: &str = "disrobe-pass-swift-objc::local-app-nibs";

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/mobile/nib")
}

fn reference(path: &Path) -> BTreeMap<String, Value> {
    serde_json::from_slice(&std::fs::read(path).expect("reference json")).expect("json")
}

fn number(value: &Value) -> f64 {
    value.as_f64().expect("reference number")
}

fn value_matches(value: &NibValue, kind: i64, expected: &Value) -> bool {
    match (value, kind) {
        (NibValue::Int8 { value }, 0) => expected.as_i64() == Some(i64::from(*value)),
        (NibValue::Int16 { value }, 1) => expected.as_i64() == Some(i64::from(*value)),
        (NibValue::Int32 { value }, 2) => expected.as_i64() == Some(i64::from(*value)),
        (NibValue::Int64 { value }, 3) => expected.as_i64() == Some(*value),
        (NibValue::Bool { value: true }, 4) => expected.as_bool() == Some(true),
        (NibValue::Bool { value: false }, 5) => expected.as_bool() == Some(false),
        (NibValue::Float { value }, 6) => expected.as_f64() == Some(f64::from(*value)),
        (NibValue::Double { value }, 7) => expected.as_f64() == Some(*value),
        (NibValue::Data { hex, numbers }, 8) => match expected {
            Value::String(text) => text == hex,
            Value::Object(object) => {
                let wanted: Vec<f64> = object["numbers"]
                    .as_array()
                    .expect("numbers")
                    .iter()
                    .map(number)
                    .collect();
                numbers.as_deref() == Some(wanted.as_slice())
            }
            _ => false,
        },
        (NibValue::Nil, 9) => expected.is_null(),
        (NibValue::Object { index }, 10) => expected.as_u64() == Some(u64::from(*index)),
        _ => false,
    }
}

fn mismatches(archive: &NibArchive, expected: &Value) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if Some(u64::from(archive.format_version)) != expected["format_version"].as_u64()
        || Some(u64::from(archive.coder_version)) != expected["coder_version"].as_u64()
    {
        found.push("header versions differ".to_owned());
    }
    let classes: Vec<(String, Vec<i64>)> = expected["classes"]
        .as_array()
        .expect("classes")
        .iter()
        .map(|class: &Value| {
            (
                class[0].as_str().expect("class name").to_owned(),
                class[1]
                    .as_array()
                    .expect("extras")
                    .iter()
                    .map(|extra: &Value| extra.as_i64().expect("extra"))
                    .collect(),
            )
        })
        .collect();
    let decoded_classes: Vec<(String, Vec<i64>)> = archive
        .classes
        .iter()
        .map(|class| {
            (
                class.name.clone(),
                class
                    .extras
                    .iter()
                    .map(|extra: &i32| i64::from(*extra))
                    .collect(),
            )
        })
        .collect();
    if classes != decoded_classes {
        found.push(format!("classes differ: {decoded_classes:?}"));
    }
    let objects: &Vec<Value> = expected["objects"].as_array().expect("objects");
    if objects.len() != archive.objects.len() {
        found.push(format!(
            "{} objects, reference has {}",
            archive.objects.len(),
            objects.len()
        ));
        return found;
    }
    for (object, wanted) in archive.objects.iter().zip(objects) {
        if Some(object.class.as_str()) != wanted[0].as_str() {
            found.push(format!("object {} class {}", object.index, object.class));
        }
        let entries: &Vec<Value> = wanted[1].as_array().expect("values");
        if entries.len() != object.entries.len() {
            found.push(format!("object {} entry count", object.index));
            continue;
        }
        for (entry, wanted_entry) in object.entries.iter().zip(entries) {
            let kind: i64 = wanted_entry[1].as_i64().expect("type");
            if Some(entry.key.as_str()) != wanted_entry[0].as_str()
                || !value_matches(&entry.value, kind, &wanted_entry[2])
            {
                found.push(format!(
                    "object {} entry {} = {:?}, reference {wanted_entry}",
                    object.index, entry.key, entry.value
                ));
            }
        }
    }
    found
}

fn grade_directory(directory: &Path) -> usize {
    let expected: BTreeMap<String, Value> = reference(&directory.join("reference.json"));
    assert!(!expected.is_empty());
    let mut objects: usize = 0;
    for (name, wanted) in &expected {
        let bytes: Vec<u8> = std::fs::read(directory.join(name)).expect("nib");
        let archive: NibArchive =
            decode_nib_archive(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        let found: Vec<String> = mismatches(&archive, wanted);
        assert!(
            found.is_empty(),
            "{name}: {:?}",
            &found[..found.len().min(8)]
        );
        objects += archive.objects.len();
    }
    objects
}

fn committed_reference() -> BTreeMap<String, Value> {
    reference(&corpus().join("reference.json"))
}

fn committed(name: &str) -> Vec<u8> {
    std::fs::read(corpus().join("sdcalertview").join(name)).expect("committed nib")
}

#[test]
fn committed_nibs_match_the_reference_parser() {
    let expected: BTreeMap<String, Value> = committed_reference();
    assert_eq!(expected.len(), 3);
    for (name, wanted) in &expected {
        let archive: NibArchive = decode_nib_archive(&committed(name)).expect("decode");
        let found: Vec<String> = mismatches(&archive, wanted);
        assert!(found.is_empty(), "{name}: {found:?}");
        assert_eq!(archive.trailing_bytes, 0, "{name}");
        assert!(!archive.objects.is_empty(), "{name}");
    }
}

#[test]
fn a_changed_key_name_is_caught() {
    let mut bytes: Vec<u8> = committed("TextFieldCell.nib");
    let keys_offset: usize = usize::try_from(u32::from_le_bytes(
        bytes[30..34].try_into().expect("offset"),
    ))
    .expect("offset");
    bytes[keys_offset + 1] ^= 0x20;
    let archive: NibArchive = decode_nib_archive(&bytes).expect("still decodes");
    let wanted: Value = committed_reference()["TextFieldCell.nib"].clone();
    assert!(!mismatches(&archive, &wanted).is_empty());
}

#[test]
fn outlets_and_custom_classes_follow_the_reference_graph() {
    for (name, wanted) in committed_reference() {
        let objects: &Vec<Value> = wanted["objects"].as_array().expect("objects");
        let string_of = |index: u64| -> Option<String> {
            let object: &Value = &objects[usize::try_from(index).ok()?];
            if object[0].as_str()? != "NSString" {
                return None;
            }
            let hex: &str = object[1]
                .as_array()?
                .iter()
                .find(|entry: &&Value| entry[0] == "NS.bytes")?[2]
                .as_str()?;
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|at: usize| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
                .collect();
            String::from_utf8(bytes).ok()
        };
        let reference_of = |object: &Value, key: &str| -> Option<u64> {
            object[1]
                .as_array()?
                .iter()
                .find(|entry: &&Value| entry[0] == key && entry[1] == 10)?[2]
                .as_u64()
        };
        let mut expected_outlets: Vec<(Option<String>, Option<String>, Option<String>)> = objects
            .iter()
            .filter(|object: &&Value| object[0] == "UIRuntimeOutletConnection")
            .map(|object: &Value| {
                let class_of = |index: Option<u64>| -> Option<String> {
                    let target: &Value = &objects[usize::try_from(index?).ok()?];
                    if target[0] == "UIClassSwapper"
                        && let Some(name) = reference_of(target, "UIClassName").and_then(string_of)
                    {
                        return Some(name);
                    }
                    Some(target[0].as_str()?.to_owned())
                };
                (
                    reference_of(object, "UILabel").and_then(string_of),
                    class_of(reference_of(object, "UISource")),
                    class_of(reference_of(object, "UIDestination")),
                )
            })
            .collect();
        expected_outlets.sort();
        let archive: NibArchive = decode_nib_archive(&committed(&name)).expect("decode");
        let mut outlets: Vec<(Option<String>, Option<String>, Option<String>)> = archive
            .connections
            .iter()
            .filter(|connection: &&NibConnection| connection.kind == "outlet")
            .map(|connection: &NibConnection| {
                (
                    connection.label.clone(),
                    connection.source_class.clone(),
                    connection.destination_class.clone(),
                )
            })
            .collect();
        outlets.sort();
        assert!(!expected_outlets.is_empty(), "{name}");
        assert!(
            expected_outlets.iter().all(|outlet| outlet.0.is_some()),
            "{name}"
        );
        assert_eq!(outlets, expected_outlets, "{name}");
        let swapped: Vec<String> = objects
            .iter()
            .filter(|object: &&Value| object[0] == "UIClassSwapper")
            .filter_map(|object: &Value| reference_of(object, "UIClassName").and_then(string_of))
            .collect::<std::collections::BTreeSet<String>>()
            .into_iter()
            .collect();
        assert_eq!(archive.custom_classes, swapped, "{name}");
    }
}

#[test]
fn trailing_bytes_are_counted_not_parsed() {
    let mut bytes: Vec<u8> = committed("ActionCell.runtime.nib");
    bytes.extend_from_slice(b"LNE\0");
    let archive: NibArchive = decode_nib_archive(&bytes).expect("decode");
    assert_eq!(archive.trailing_bytes, 4);
    let wanted: Value = committed_reference()["ActionCell.runtime.nib"].clone();
    assert!(mismatches(&archive, &wanted).is_empty());
}

#[test]
fn corrupted_nibs_are_refused_or_read_without_panicking() {
    let seeds: [Vec<u8>; 3] = [
        committed("TextFieldCell.nib"),
        committed("ActionCell.runtime.nib"),
        committed("ActionCell.objects-12.3+.nib"),
    ];
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut refused: usize = 0;
    for round in 0..400_usize {
        let mut bytes: Vec<u8> = seeds[round % seeds.len()].clone();
        let len: u64 = u64::try_from(bytes.len()).expect("length");
        if round % 5 == 4 {
            bytes.truncate(usize::try_from(next() % len).expect("cut"));
        } else {
            for _ in 0..=(next() % 8) {
                let index: usize = usize::try_from(next() % len).expect("index");
                bytes[index] = u8::try_from(next() & 0xff).expect("byte");
            }
        }
        if let Err(error) = decode_nib_archive(&bytes) {
            assert!(error.to_string().starts_with("DR-IOS-"), "{error}");
            refused += 1;
        }
    }
    assert!(refused > 0);
}

#[test]
fn local_app_nibs_match_the_reference_parser() {
    let directory: PathBuf = scratch_root().join("nib-local");
    if !directory.join("reference.json").is_file() {
        let what: String = format!(
            "compiled NIBs from the local, non-redistributable OnionBrowser and Feather IPAs with their \
             dump_nib_reference.py output at {}",
            directory.display()
        );
        match disrobe_testkit::require::<()>(LOCAL_PREREQUISITE, &what, None) {
            Ok(_) => return,
            Err(error) => panic!("{LOCAL_PREREQUISITE}: {error}"),
        }
    }
    let objects: usize = grade_directory(&directory);
    assert!(objects > 2000, "{objects}");
}

#[test]
fn the_chain_pass_claims_nibs_and_writes_the_decoded_graph() {
    for name in committed_reference().keys() {
        let bytes: Vec<u8> = committed(name);
        let context: DetectContext<'_> = DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let verdict: DetectVerdict = AppleArchiveDetector
            .detect(&context)
            .unwrap_or_else(|| panic!("{name} not claimed"));
        assert_eq!(verdict.format_tag, "apple-nib-archive", "{name}");
        let output: Artifact = APPLE_ARCHIVE_PASS
            .run(&Artifact::new(Rung::Raw, bytes.clone(), [0u8; 32]))
            .expect("pass output");
        let report: Value = serde_json::from_slice(&output.envelope).expect("json report");
        let direct: NibArchive = decode_nib_archive(&bytes).expect("decode");
        assert_eq!(
            report["objects"].as_array().expect("objects").len(),
            direct.objects.len(),
            "{name}"
        );
        assert_eq!(
            report["connections"].as_array().expect("connections").len(),
            direct.connections.len(),
            "{name}"
        );
    }
    let mut broken: Vec<u8> = committed("TextFieldCell.nib");
    broken.truncate(60);
    let context: DetectContext<'_> = DetectContext {
        bytes: &broken,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    assert!(AppleArchiveDetector.detect(&context).is_none());
}
