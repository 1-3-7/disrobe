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

pub fn recovery_json_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json")
}

pub fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = recovery_json_path();
    let raw: String = fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "a published figure is graded against {}, so a run that cannot read it must fail \
             rather than measure nothing: {error}",
            path.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|heading: &str| heading.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

pub fn published_count(heading_needle: &str, label: &str) -> u64 {
    let bar: serde_json::Value = published_bar(heading_needle, label);
    bar["value"].as_u64().unwrap_or_else(|| {
        panic!(
            "the `{label}` bar publishes a count, so its value must be a whole number; \
             recovery.json carries {}",
            bar["value"]
        )
    })
}
