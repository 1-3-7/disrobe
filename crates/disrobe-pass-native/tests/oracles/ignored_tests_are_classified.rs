#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CLASSES: [&str; 4] = ["toolchain: ", "fixture: ", "cost: ", "environment: "];
const IGNORE_ATTRIBUTE: &str = "#[ignore";
const EXPECTED_TOTAL: usize = 76;
const EXPECTED_PER_CLASS: [(&str, usize); 4] = [
    ("toolchain: ", 68),
    ("fixture: ", 5),
    ("cost: ", 1),
    ("environment: ", 2),
];

fn tests_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries: std::fs::ReadDir = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()));
        for entry in entries.filter_map(Result::ok) {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn ignore_reasons(source: &str) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with(IGNORE_ATTRIBUTE) {
            continue;
        }
        let Some(rest): Option<&str> = trimmed.strip_prefix(IGNORE_ATTRIBUTE) else {
            continue;
        };
        let Some(opened): Option<&str> = rest.split_once('"').map(|(_, tail)| tail) else {
            reasons.push(String::new());
            continue;
        };
        let reason: &str = opened.split('"').next().unwrap_or_default();
        reasons.push(reason.to_owned());
    }
    reasons
}

#[test]
fn every_ignored_test_names_one_blocker_class() {
    let root: PathBuf = tests_root();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut total: usize = 0;
    let mut unclassified: Vec<String> = Vec::new();

    for path in rust_sources(&root) {
        let source: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let relative: String = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for reason in ignore_reasons(&source) {
            total = total.saturating_add(1);
            match CLASSES
                .iter()
                .find(|class: &&&str| reason.starts_with(**class))
            {
                Some(class) => *counts.entry(class).or_default() += 1,
                None => unclassified.push(format!("{relative}: {reason:?}")),
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "every #[ignore] in this crate must open with one of {CLASSES:?} and then name the \
         concrete missing thing, so the audit stays repeatable; these do not:\n  {}",
        unclassified.join("\n  ")
    );
    assert_eq!(
        total, EXPECTED_TOTAL,
        "the number of ignored tests changed; classify the new one and update the pin"
    );
    for (class, expected) in EXPECTED_PER_CLASS {
        assert_eq!(
            counts.get(class).copied().unwrap_or_default(),
            expected,
            "the {class:?} population changed; a test moving between classes must be deliberate"
        );
    }
}

#[test]
fn no_ignore_reason_still_blames_an_unverified_platform_matrix() {
    let root: PathBuf = tests_root();
    let mut stale: Vec<String> = Vec::new();
    for path in rust_sources(&root) {
        let source: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for reason in ignore_reasons(&source) {
            let lowered: String = reason.to_ascii_lowercase();
            if lowered.contains("platform matrix") || lowered.contains("fixture pending") {
                stale.push(format!("{}: {reason:?}", path.display()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "these reasons state a generic phrase rather than the blocker they carry:\n  {}",
        stale.join("\n  ")
    );
}
