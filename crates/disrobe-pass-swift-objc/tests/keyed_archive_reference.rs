#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_swift_objc::keyed_archive::{ArchivedValue, KeyedArchive, decode_keyed_archive};
use serde_json::{Value, json};

struct Generated {
    dir: ScratchDir,
    truth: Value,
}

fn python() -> String {
    ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| {
            Command::new(candidate)
                .args(["-c", "import plistlib; plistlib.UID(1)"])
                .status()
                .is_ok_and(|status: std::process::ExitStatus| status.success())
        })
        .map_or_else(
            || panic!("the keyed-archive grader needs CPython 3.8 or later (plistlib.UID) to write its archives"),
            str::to_owned,
        )
}

fn generated() -> &'static Generated {
    static GENERATED: OnceLock<Generated> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let dir: ScratchDir = ScratchDir::create("keyed-archives").expect("scratch");
        let script: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/make_keyed_archives.py");
        let status: std::process::ExitStatus = Command::new(python())
            .arg(&script)
            .arg(dir.path())
            .status()
            .expect("run the archive writer");
        assert!(status.success(), "make_keyed_archives.py failed");
        let truth: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("truth.json")).expect("truth"))
                .expect("truth JSON");
        Generated { dir, truth }
    })
}

fn archive(name: &str) -> Vec<u8> {
    std::fs::read(generated().dir.path().join(name)).expect("generated archive")
}

fn canonical(value: &ArchivedValue) -> Value {
    match value {
        ArchivedValue::Null => Value::Null,
        ArchivedValue::Bool { value } => json!(value),
        ArchivedValue::Integer { value } => i64::try_from(*value).map_or_else(
            |_| json!(u64::try_from(*value).unwrap_or_default()),
            |v| json!(v),
        ),
        ArchivedValue::Real { value } => json!(value),
        ArchivedValue::String { value } => json!(value),
        ArchivedValue::Data { hex } => json!({ "data": hex }),
        ArchivedValue::Date {
            seconds_since_2001, ..
        } => json!({ "date": seconds_since_2001 }),
        ArchivedValue::Array { class, items } => {
            json!({ "array": class, "items": items.iter().map(canonical).collect::<Vec<Value>>() })
        }
        ArchivedValue::Set { class, items } => {
            json!({ "set": class, "items": items.iter().map(canonical).collect::<Vec<Value>>() })
        }
        ArchivedValue::Dictionary { class, entries } => json!({
            "dict": class,
            "entries": entries
                .iter()
                .map(|(key, value)| json!([canonical(key), canonical(value)]))
                .collect::<Vec<Value>>(),
        }),
        ArchivedValue::Url { base, relative } => json!({
            "url": {
                "base": base.as_deref().map_or(Value::Null, canonical),
                "relative": canonical(relative),
            }
        }),
        ArchivedValue::Uuid { value } => json!({ "uuid": value }),
        ArchivedValue::Value { class, fields } => json!({
            "value": class,
            "fields": fields.iter().map(|(k, v)| (k.clone(), canonical(v))).collect::<serde_json::Map<String, Value>>(),
        }),
        ArchivedValue::Object {
            class,
            superclasses,
            fields,
        } => json!({
            "object": class,
            "superclasses": superclasses,
            "fields": fields.iter().map(|(k, v)| (k.clone(), canonical(v))).collect::<serde_json::Map<String, Value>>(),
        }),
        ArchivedValue::BackReference { uid } => json!({ "backref": uid }),
        ArchivedValue::Dangling { uid } => json!({ "dangling": uid }),
        ArchivedValue::Truncated => json!({ "truncated": true }),
    }
}

fn top(decoded: &KeyedArchive) -> Value {
    Value::Object(
        decoded
            .top
            .iter()
            .map(|(key, value)| (key.clone(), canonical(value)))
            .collect(),
    )
}

#[test]
fn every_archive_decodes_to_the_graph_the_writer_built() {
    let truth: &Value = &generated().truth;
    for (name, expected) in truth.as_object().expect("truth") {
        let decoded: KeyedArchive = decode_keyed_archive(&archive(name)).expect("archive decodes");
        assert_eq!(decoded.archiver, "NSKeyedArchiver", "{name}");
        assert_eq!(decoded.version, Some(100_000), "{name}");
        assert_eq!(top(&decoded), expected["top"], "{name}");
        if name.starts_with("dangling") {
            assert!(
                decoded
                    .problems
                    .iter()
                    .any(|problem| problem.contains("999")),
                "{:?}",
                decoded.problems
            );
        } else {
            assert!(
                decoded.problems.is_empty(),
                "{name}: {:?}",
                decoded.problems
            );
        }
    }
}

#[test]
fn a_changed_string_or_uid_is_caught_by_the_grader() {
    let truth: &Value = &generated().truth;
    let mut renamed: Vec<u8> = archive("graph.bplist");
    let at: usize = renamed
        .windows(5)
        .position(|window: &[u8]| window == b"Alice")
        .expect("Alice in the archive");
    renamed[at + 4] = b'f';
    let decoded: KeyedArchive = decode_keyed_archive(&renamed).expect("still decodes");
    assert_ne!(top(&decoded), truth["graph.bplist"]["top"]);

    let mut rewired: Vec<u8> = archive("basic.xml");
    let text: String = String::from_utf8(rewired.clone()).expect("xml text");
    let first_uid: usize = text.find("<integer>").expect("an integer");
    rewired[first_uid + "<integer>".len()] = b'9';
    if let Ok(decoded) = decode_keyed_archive(&rewired) {
        assert_ne!(top(&decoded), truth["basic.xml"]["top"]);
    }
}

#[test]
fn deep_and_self_referencing_graphs_stay_bounded() {
    let mut objects: Vec<plist::Value> = vec![plist::Value::String("$null".to_owned())];
    let class: plist::Dictionary = [
        (
            "$classname".to_owned(),
            plist::Value::String("NSArray".to_owned()),
        ),
        (
            "$classes".to_owned(),
            plist::Value::Array(vec![
                plist::Value::String("NSArray".to_owned()),
                plist::Value::String("NSObject".to_owned()),
            ]),
        ),
    ]
    .into_iter()
    .collect();
    objects.push(plist::Value::Dictionary(class));
    let depth: u64 = 5_000;
    for level in 0..depth {
        let next: u64 = level + 3;
        let items: Vec<plist::Value> = if level + 1 < depth {
            vec![plist::Value::Uid(plist::Uid::new(next))]
        } else {
            Vec::new()
        };
        let node: plist::Dictionary = [
            ("$class".to_owned(), plist::Value::Uid(plist::Uid::new(1))),
            ("NS.objects".to_owned(), plist::Value::Array(items)),
        ]
        .into_iter()
        .collect();
        objects.push(plist::Value::Dictionary(node));
    }
    let root: plist::Dictionary = [
        (
            "$archiver".to_owned(),
            plist::Value::String("NSKeyedArchiver".to_owned()),
        ),
        ("$version".to_owned(), plist::Value::Integer(100_000.into())),
        (
            "$top".to_owned(),
            plist::Value::Dictionary(
                std::iter::once(("root".to_owned(), plist::Value::Uid(plist::Uid::new(2))))
                    .collect(),
            ),
        ),
        ("$objects".to_owned(), plist::Value::Array(objects)),
    ]
    .into_iter()
    .collect();
    let mut bytes: Vec<u8> = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(root)).expect("write");
    let decoded: KeyedArchive = decode_keyed_archive(&bytes).expect("deep archive decodes");
    assert!(
        decoded
            .problems
            .iter()
            .any(|problem| problem.contains("levels")),
        "{:?}",
        decoded.problems
    );
}

#[test]
fn corrupted_archives_give_a_tree_or_a_typed_error() {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for name in ["basic.bplist", "graph.bplist", "basic.xml"] {
        let original: Vec<u8> = archive(name);
        for round in 0..200 {
            let mut bytes: Vec<u8> = original.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for flip in 0..=(state % 6) {
                let at: usize = ((state >> (flip * 5)) % bytes.len() as u64) as usize;
                bytes[at] = (state >> (flip % 8 * 8)) as u8;
            }
            if round % 5 == 0 {
                bytes.truncate((state % bytes.len() as u64) as usize);
            }
            let _ = decode_keyed_archive(&bytes);
        }
    }
}
