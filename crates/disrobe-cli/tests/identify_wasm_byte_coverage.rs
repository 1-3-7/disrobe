#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::ops::Range;
use std::path::{Path, PathBuf};

use common::{Run, run_disrobe};
use wasmparser::{Parser, Payload};

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn blazor_wasm() -> PathBuf {
    let path: PathBuf = workspace_root()
        .join("corpus")
        .join("binfmt")
        .join("blazor")
        .join("Bz.belq8bx71h.wasm");
    assert!(path.is_file(), "missing tracked Blazor Wasm fixture");
    path
}

fn run_identify(path: &Path, json: bool) -> Run {
    let path_text: &str = path.to_str().expect("fixture path is Unicode");
    if json {
        run_disrobe(&["identify", path_text, "--coverage", "--json"])
    } else {
        run_disrobe(&["identify", path_text, "--coverage"])
    }
}

fn reference_payload_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let parsed: Payload<'_> = payload.expect("wasmparser accepts the tracked Blazor module");
        let section: Option<(u8, Range<usize>)> = parsed.as_section();
        if let Some((_id, range)) = section {
            ranges.push(range);
        }
    }
    ranges
}

fn disrobe_payload_ranges(report: &serde_json::Value) -> Vec<Range<usize>> {
    report["coverage"]["regions"]
        .as_array()
        .expect("coverage regions")
        .iter()
        .filter_map(|region: &serde_json::Value| {
            let claimant: &str = region["claimant"].as_str()?;
            claimant.ends_with("-payload").then(|| {
                let start: usize = region["start"].as_u64().expect("region start") as usize;
                let end: usize = region["end"].as_u64().expect("region end") as usize;
                start..end
            })
        })
        .collect()
}

#[test]
fn tracked_blazor_payload_ranges_match_wasmparser_and_json_is_deterministic() {
    let path: PathBuf = blazor_wasm();
    let bytes: Vec<u8> = std::fs::read(&path).expect("read tracked Blazor Wasm");
    let first: Run = run_identify(&path, true);
    let second: Run = run_identify(&path, true);
    assert_eq!(first.code, 0, "{}", first.stderr);
    assert_eq!(second.code, 0, "{}", second.stderr);
    assert_eq!(first.stdout, second.stdout);

    let report: serde_json::Value = serde_json::from_str(&first.stdout).expect("identify JSON");
    assert_eq!(report["format"], "wasm");
    assert_eq!(report["coverage"]["format"], "wasm");
    assert_eq!(report["coverage"]["file_len"], bytes.len() as u64);
    assert_eq!(report["coverage"]["claimed_bytes"], bytes.len() as u64);
    assert_eq!(report["coverage"]["unclaimed_bytes"], 0);
    assert_eq!(report["coverage"]["complete"], true);
    assert_eq!(
        disrobe_payload_ranges(&report),
        reference_payload_ranges(&bytes)
    );
}

#[test]
fn human_identify_reports_coherent_wasm_format_and_complete_accounting() {
    let path: PathBuf = blazor_wasm();
    let output: Run = run_identify(&path, false);
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert!(output.stdout.contains("format: wasm"), "{}", output.stdout);
    assert!(
        output
            .stdout
            .contains("bytes accounted for: 17173 of 17173 (100.00%)"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("unclaimed 0, slack 0, missing 0"),
        "{}",
        output.stdout
    );
}
