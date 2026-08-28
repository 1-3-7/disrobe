#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_binfmt::container::{ContainerKind, ExtractionMode};

const ROSTER: &str = "tests/golden/container_roster.txt";

const PUBLISHED_BAR: &str = "Containers";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn declared_rows() -> Vec<String> {
    let mut rows: Vec<String> = ContainerKind::ALL
        .iter()
        .map(|kind: &ContainerKind| {
            format!("{}\t{}", kind.label(), mode_name(kind.extraction_mode()))
        })
        .collect();
    rows.sort_unstable();
    rows
}

const fn mode_name(mode: ExtractionMode) -> &'static str {
    match mode {
        ExtractionMode::Payload => "payload",
        ExtractionMode::MetadataOnly => "metadata-only",
        ExtractionMode::ExternalTool => "external-tool",
        ExtractionMode::Unsupported => "unsupported",
    }
}

fn roster_rows() -> Vec<String> {
    let path: PathBuf = crate_root().join(ROSTER);
    let raw: String = std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} pins the container roster the published figure is derived from, so its absence \
             leaves that figure unbound: {error}",
            path.display()
        )
    });
    raw.lines()
        .map(str::trim_end)
        .filter(|line: &&str| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn published(field: &str) -> u64 {
    let path: PathBuf = crate_root()
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()));
    for group in parsed["groups"].as_array().expect("groups array") {
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(PUBLISHED_BAR) {
                return bar[field]
                    .as_u64()
                    .unwrap_or_else(|| panic!("the {PUBLISHED_BAR} bar must record {field}"));
            }
        }
    }
    panic!("recovery.json must carry a {PUBLISHED_BAR} bar")
}

#[test]
fn the_roster_names_every_container_the_enum_declares() {
    let declared: Vec<String> = declared_rows();
    let pinned: Vec<String> = roster_rows();

    let missing: Vec<&String> = declared
        .iter()
        .filter(|row: &&String| !pinned.contains(row))
        .collect();
    let stale: Vec<&String> = pinned
        .iter()
        .filter(|row: &&String| !declared.contains(row))
        .collect();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "the roster at {ROSTER} and the enum disagree, and a bare total would have stayed green \
         through that. Absent from the roster: {missing:?}. No longer declared: {stale:?}"
    );
    assert_eq!(
        pinned, declared,
        "the roster must list each container once, in label order"
    );
}

#[test]
fn the_published_detected_count_is_the_roster_counted_by_name() {
    let pinned: Vec<String> = roster_rows();
    let payload: usize = pinned
        .iter()
        .filter(|row: &&String| row.ends_with("\tpayload"))
        .count();
    let metadata_only: Vec<&String> = pinned
        .iter()
        .filter(|row: &&String| row.ends_with("\tmetadata-only"))
        .collect();

    assert_eq!(
        u64::try_from(pinned.len()).expect("roster length fits u64"),
        published("detected"),
        "recovery.json publishes a detected count that no longer matches the {} formats named in \
         {ROSTER}",
        pinned.len()
    );
    assert_eq!(metadata_only, ["luks1\tmetadata-only"]);
    assert_eq!(payload + metadata_only.len(), pinned.len());
    assert!(
        published("delivered") <= u64::try_from(payload).expect("payload count fits u64"),
        "recovery.json publishes a delivered count above the {payload} formats {ROSTER} names as \
         carrying an extractor. Delivered is measured by \
         crates/disrobe-cli/tests/container_breadth.rs over committed inputs and is bound to that \
         run by published_container_counts_match_this_enum; this roster counts declarations and \
         must never be what makes the delivered figure true"
    );
}

#[test]
fn the_roster_is_a_second_statement_and_not_generated_at_read_time() {
    let path: PathBuf = crate_root().join(ROSTER);
    assert!(
        Path::new(&path).is_file(),
        "the roster has to be a committed file, or the comparison compares the enum with itself"
    );
    let raw: String = std::fs::read_to_string(&path).expect("read roster");
    assert!(
        raw.lines().count() >= ContainerKind::ALL.len(),
        "the roster holds {} lines against {} declared containers",
        raw.lines().count(),
        ContainerKind::ALL.len()
    );
}
