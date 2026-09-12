#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const REGISTRY: &str = "crates/disrobe-passes/src/lib.rs";
const DETECTOR: &str = "chain_detector.rs";
const MARKER: &str = "::chain_detector::";

const UNREGISTERED_BY_DESIGN: [&str; 0] = [];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn crate_identifier(manifest: &Path) -> String {
    let text: String = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
    let name: &str = text
        .lines()
        .find_map(|line: &str| line.strip_prefix("name = "))
        .unwrap_or_else(|| panic!("{} declares no package name", manifest.display()));
    name.trim().trim_matches('"').replace('-', "_")
}

fn crates_shipping_a_detector(root: &Path) -> BTreeMap<String, PathBuf> {
    let crates_dir: PathBuf = root.join("crates");
    let entries: std::fs::ReadDir = std::fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", crates_dir.display()));
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in entries {
        let path: PathBuf = entry.expect("crate directory entry").path();
        let detector: PathBuf = path.join("src").join(DETECTOR);
        if !detector.exists() {
            continue;
        }
        let manifest: PathBuf = path.join("Cargo.toml");
        found.insert(crate_identifier(&manifest), detector);
    }
    found
}

fn crates_named_by_the_registry(root: &Path) -> BTreeSet<String> {
    let registry: PathBuf = root.join(REGISTRY);
    let text: String = std::fs::read_to_string(&registry)
        .unwrap_or_else(|e| panic!("read {}: {e}", registry.display()));
    let mut named: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let Some(marker_at): Option<usize> = line.find(MARKER) else {
            continue;
        };
        let head: &str = &line[..marker_at];
        let identifier: String = head
            .chars()
            .rev()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .collect();
        if !identifier.is_empty() {
            named.insert(identifier);
        }
    }
    named
}

#[test]
fn every_crate_that_ships_a_chain_detector_is_registered() {
    let root: PathBuf = workspace_root();
    let shipping: BTreeMap<String, PathBuf> = crates_shipping_a_detector(&root);
    assert!(
        shipping.len() >= 20,
        "only {} crate(s) ship a {DETECTOR}; the sweep found almost nothing, so it is measuring the wrong tree",
        shipping.len()
    );
    let registered: BTreeSet<String> = crates_named_by_the_registry(&root);
    assert!(
        registered.len() >= 20,
        "the registry names only {} crate(s); the parse is wrong, not the registry",
        registered.len()
    );

    let missing: Vec<&String> = shipping
        .keys()
        .filter(|name: &&String| !registered.contains(*name))
        .filter(|name: &&String| !UNREGISTERED_BY_DESIGN.contains(&name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these crates ship a {DETECTOR} but no line of {REGISTRY} registers them, so `disrobe auto` can never route to them and no chain test covers them: {missing:?}"
    );
}

#[test]
fn the_registry_names_no_crate_that_ships_no_detector() {
    let root: PathBuf = workspace_root();
    let shipping: BTreeMap<String, PathBuf> = crates_shipping_a_detector(&root);
    let registered: BTreeSet<String> = crates_named_by_the_registry(&root);
    let stale: Vec<&String> = registered
        .iter()
        .filter(|name: &&String| !shipping.contains_key(*name))
        .collect();
    assert!(
        stale.is_empty(),
        "{REGISTRY} names these crates through {MARKER} but they ship no src/{DETECTOR}: {stale:?}"
    );
}

#[test]
fn no_pass_is_registered_twice_under_the_same_constant() {
    let root: PathBuf = workspace_root();
    let registry: PathBuf = root.join(REGISTRY);
    let text: String = std::fs::read_to_string(&registry)
        .unwrap_or_else(|e| panic!("read {}: {e}", registry.display()));
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("r.register(") {
            continue;
        }
        let Some(marker_at): Option<usize> = trimmed.find(MARKER) else {
            continue;
        };
        let path: String = trimmed[..marker_at]
            .trim_start_matches("r.register(&")
            .to_owned();
        let constant: String = trimmed[marker_at + MARKER.len()..]
            .chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let key: String = format!("{path}{MARKER}{constant}");
        *seen.entry(key).or_default() += 1;
    }
    assert!(
        !seen.is_empty(),
        "no registration line parsed out of {REGISTRY}; the shape changed and this gate is measuring nothing"
    );
    let duplicates: Vec<(&String, &usize)> = seen
        .iter()
        .filter(|(_, count): &(&String, &usize)| **count > 1)
        .collect();
    assert!(
        duplicates.is_empty(),
        "these passes are registered more than once, which silently shadows or double-runs them: {duplicates:?}"
    );
}
