#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn recovery_json_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json")
}

fn recovery_document() -> serde_json::Value {
    let path: PathBuf = recovery_json_path();
    let raw: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "a published figure is graded against {}, so a run that cannot read it must fail \
             rather than measure nothing: {error}",
            path.display()
        )
    });
    serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()))
}

pub(crate) fn published_group(heading: &str) -> serde_json::Value {
    let doc: serde_json::Value = recovery_document();
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        if group["heading"].as_str() == Some(heading) {
            found.push(group.clone());
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one group whose heading is exactly `{heading}`, \
         found {}; a figure that cannot be located is never a pass",
        found.len()
    );
    found.remove(0)
}

pub(crate) fn published_bar(heading: &str, label: &str) -> serde_json::Value {
    let group: serde_json::Value = published_group(heading);
    let mut found: Vec<serde_json::Value> = Vec::new();
    for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
        if bar["label"].as_str() == Some(label) {
            found.push(bar.clone());
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under the group \
         headed `{heading}`, found {}",
        found.len()
    );
    found.remove(0)
}

pub(crate) fn published_u64(heading: &str, label: &str, field: &str) -> u64 {
    let bar: serde_json::Value = published_bar(heading, label);
    bar[field].as_u64().unwrap_or_else(|| {
        panic!(
            "the `{label}` bar under `{heading}` must publish a whole-number `{field}`; \
             recovery.json carries {}",
            bar[field]
        )
    })
}

pub(crate) fn published_f64(heading: &str, label: &str, field: &str) -> f64 {
    let bar: serde_json::Value = published_bar(heading, label);
    bar[field].as_f64().unwrap_or_else(|| {
        panic!(
            "the `{label}` bar under `{heading}` must publish a numeric `{field}`; recovery.json \
             carries {}",
            bar[field]
        )
    })
}
