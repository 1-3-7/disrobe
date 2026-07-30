#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::{ToolchainBanner, require_mri_measured_series};

const HELLO_FLOOR_PCT: u32 = 100;
const GREETER_FLOOR_PCT: u32 = 100;
const MEGAFILE_FLOOR_PCT: u32 = 98;

const HELLO_MATCHED_FLOOR: u32 = 4;
const GREETER_MATCHED_FLOOR: u32 = 79;
const MEGAFILE_MATCHED_FLOOR: u32 = 23_580;

const HELLO_COMPARED_TOTAL: u32 = 4;
const GREETER_COMPARED_TOTAL: u32 = 79;
const MEGAFILE_COMPARED_TOTAL: u32 = 23_966;

const PUBLISHED_HEADING: &str = "Ruby YARV";
const PUBLISHED_GREETER_BAR: &str = "greeter";
const PUBLISHED_MEGAFILE_BAR: &str = "megafile";

const GRADED: &str =
    "the YARV recompile differential over hello.rb, greeter.rb and megafile/edge_cases.rb";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecompileMode {
    Whole,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Measurement {
    mode: RecompileMode,
    matched: u32,
    compared: u32,
    pct: u32,
}

#[derive(Debug, Clone, Copy)]
struct Fixture {
    label: &'static str,
    original_rel: &'static str,
    yarvc_rel: &'static str,
    floor_pct: u32,
    matched_floor: u32,
    compared_total: u32,
    published_bar: Option<&'static str>,
}

const FIXTURES: [Fixture; 3] = [
    Fixture {
        label: "hello",
        original_rel: "hello.rb",
        yarvc_rel: "mri/yarv/hello.rb.yarvc",
        floor_pct: HELLO_FLOOR_PCT,
        matched_floor: HELLO_MATCHED_FLOOR,
        compared_total: HELLO_COMPARED_TOTAL,
        published_bar: None,
    },
    Fixture {
        label: "greeter",
        original_rel: "greeter.rb",
        yarvc_rel: "mri/yarv/greeter.rb.yarvc",
        floor_pct: GREETER_FLOOR_PCT,
        matched_floor: GREETER_MATCHED_FLOOR,
        compared_total: GREETER_COMPARED_TOTAL,
        published_bar: Some(PUBLISHED_GREETER_BAR),
    },
    Fixture {
        label: "megafile",
        original_rel: "megafile/edge_cases.rb",
        yarvc_rel: "mri/yarv/edge_cases.rb.yarvc",
        floor_pct: MEGAFILE_FLOOR_PCT,
        matched_floor: MEGAFILE_MATCHED_FLOOR,
        compared_total: MEGAFILE_COMPARED_TOTAL,
        published_bar: Some(PUBLISHED_MEGAFILE_BAR),
    },
];

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("ruby");
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = corpus_dir();
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

fn recovery_json_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    path
}

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = recovery_json_path();
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
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

fn published_value(label: &str) -> f64 {
    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
    bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the {label} bar must carry a numeric value"))
}

fn published_count_defect(
    bar: &serde_json::Value,
    label: &str,
    fixture: &Fixture,
) -> Option<String> {
    let num: Option<u64> = bar.get("num").and_then(serde_json::Value::as_u64);
    let den: Option<u64> = bar.get("den").and_then(serde_json::Value::as_u64);
    match (num, den) {
        (None, None) => None,
        (Some(num), Some(den)) => {
            let want_num: u64 = u64::from(fixture.matched_floor);
            let want_den: u64 = u64::from(fixture.compared_total);
            (num != want_num || den != want_den).then(|| {
                format!(
                    "the {label} bar publishes the counts {num} of {den}, but this gate enforces \
                     {want_num} of {want_den}; a published count that no gate enforces can drift \
                     away from what the differential measures"
                )
            })
        }
        (Some(num), None) => Some(format!(
            "the {label} bar publishes the numerator {num} with no `den`, so the fraction it states \
             has no denominator to be read against"
        )),
        (None, Some(den)) => Some(format!(
            "the {label} bar publishes the denominator {den} with no `num`, so the fraction it \
             states has no numerator to be read against"
        )),
    }
}

fn fixture_for_bar(label: &str) -> &'static Fixture {
    FIXTURES
        .iter()
        .find(|fixture: &&Fixture| fixture.published_bar == Some(label))
        .unwrap_or_else(|| panic!("no fixture in this gate publishes the {label} bar"))
}

#[test]
fn published_yarv_bars_match_the_floors_this_crate_enforces() {
    let greeter: f64 = published_value(PUBLISHED_GREETER_BAR);
    let megafile: f64 = published_value(PUBLISHED_MEGAFILE_BAR);
    assert!(
        (greeter - f64::from(GREETER_FLOOR_PCT)).abs() < f64::EPSILON,
        "xtask/data/recovery.json publishes greeter at {greeter}% and every document renders that \
         number, but this gate enforces {GREETER_FLOOR_PCT}%"
    );
    assert!(
        (megafile - f64::from(MEGAFILE_FLOOR_PCT)).abs() < f64::EPSILON,
        "xtask/data/recovery.json publishes megafile at {megafile}% and every document renders \
         that number, but this gate enforces {MEGAFILE_FLOOR_PCT}%"
    );
}

#[test]
fn published_yarv_counts_match_the_counts_this_crate_enforces() {
    for label in [PUBLISHED_GREETER_BAR, PUBLISHED_MEGAFILE_BAR] {
        let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
        let fixture: &Fixture = fixture_for_bar(label);
        if let Some(defect) = published_count_defect(&bar, label, fixture) {
            panic!("{defect}");
        }
    }
}

#[test]
fn a_published_count_that_disagrees_with_this_gate_is_rejected() {
    let fixture: &Fixture = fixture_for_bar(PUBLISHED_MEGAFILE_BAR);
    let num: u64 = u64::from(fixture.matched_floor);
    let den: u64 = u64::from(fixture.compared_total);
    let agreeing: serde_json::Value = serde_json::json!({"num": num, "den": den});
    assert!(
        published_count_defect(&agreeing, PUBLISHED_MEGAFILE_BAR, fixture).is_none(),
        "counts equal to the enforced floor and total must be accepted"
    );
    for disagreeing in [
        serde_json::json!({"num": num + 1, "den": den}),
        serde_json::json!({"num": num - 1, "den": den}),
        serde_json::json!({"num": num, "den": den + 1}),
        serde_json::json!({"num": num}),
        serde_json::json!({"den": den}),
    ] {
        assert!(
            published_count_defect(&disagreeing, PUBLISHED_MEGAFILE_BAR, fixture).is_some(),
            "the counts {disagreeing} state a fraction this gate does not enforce and must be \
             rejected"
        );
    }
    assert!(
        published_count_defect(&serde_json::json!({}), PUBLISHED_MEGAFILE_BAR, fixture).is_none(),
        "a bar that publishes no counts at all is the state before the counts are published, so it \
         is tolerated; once either count appears, both must match this gate"
    );
}

fn recover_source(yarvc_rel: &str) -> String {
    let path: PathBuf = corpus_path(yarvc_rel);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "corpus/ruby/{yarvc_rel} is tracked in this repository but could not be read here \
             ({e}); an absent or unreadable fixture is never a skip, because that is how a \
             differential stops grading without saying so"
        )
    });
    let analysis = analyze_bytes(&bytes, yarvc_rel)
        .unwrap_or_else(|e| panic!("analyze corpus/ruby/{yarvc_rel}: {e}"));
    let yarv = analysis
        .yarv
        .unwrap_or_else(|| panic!("corpus/ruby/{yarvc_rel} produced no YARV analysis"));
    yarv.decompiled.source
}

fn parse_measurement(line: &str) -> Option<Measurement> {
    let mode: RecompileMode = match line
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("mode="))?
    {
        "whole" => RecompileMode::Whole,
        "partial" => RecompileMode::Partial,
        _ => return None,
    };
    let fraction: &str = line
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("matched="))?;
    let (matched_raw, compared_raw): (&str, &str) = fraction.split_once('/')?;
    let pct_raw: &str = line
        .split_whitespace()
        .find_map(|t: &str| t.strip_prefix("pct="))?;
    Some(Measurement {
        mode,
        matched: matched_raw.parse::<u32>().ok()?,
        compared: compared_raw.parse::<u32>().ok()?,
        pct: pct_raw.parse::<u32>().ok()?,
    })
}

fn measure(fixture: &Fixture) -> Measurement {
    let recovered: String = recover_source(fixture.yarvc_rel);
    let purpose: String = format!(
        "disrobe_yarv_recovered_{}",
        fixture.yarvc_rel.replace(['/', '.'], "_")
    );
    let (scratch, file): (ScratchFile, std::fs::File) = ScratchFile::create(&purpose, "rb")
        .unwrap_or_else(|e| panic!("create scratch file for {}: {e}", fixture.label));
    drop(file);
    let rec_path: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&rec_path, recovered)
        .unwrap_or_else(|e: std::io::Error| panic!("write recovered {}: {e}", fixture.label));

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path(fixture.original_rel);
    let output = Command::new("ruby")
        .arg(&oracle)
        .arg(&original)
        .arg(&rec_path)
        .output()
        .unwrap_or_else(|e: std::io::Error| {
            panic!(
                "ruby was usable a moment ago but could not run {} for {}: {e}",
                oracle.display(),
                fixture.label
            )
        });
    let line: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    println!("[{}] {line}", fixture.yarvc_rel);
    let measurement: Measurement = parse_measurement(&line).unwrap_or_else(|| {
        panic!(
            "the {} recompile run printed `{line}` (stderr `{stderr}`), which carries no \
             mode/matched/pct triple, so nothing was measured for it",
            fixture.label
        )
    });
    assert!(
        measurement.compared > 0,
        "the {} original compiled to zero opcodes, so any percentage over it would be vacuous",
        fixture.label
    );
    assert_eq!(
        measurement.pct,
        100 * measurement.matched / measurement.compared,
        "the {} run printed pct={} beside matched={}/{}, so the reported rate and the reported \
         counts disagree",
        fixture.label,
        measurement.pct,
        measurement.matched,
        measurement.compared
    );
    measurement
}

fn enforce_floors(fixture: &Fixture, measurement: &Measurement) {
    assert_eq!(
        measurement.mode,
        RecompileMode::Whole,
        "{} recovered source no longer recompiles as one unit, so its rate was scored per \
         top-level construct instead of over the whole file, which is a weaker measurement than \
         the published axis states",
        fixture.label
    );
    assert_eq!(
        measurement.compared, fixture.compared_total,
        "{} original now compiles to {} opcodes, not the {} every pinned count for it was measured \
         against; re-measure this fixture and update the published numerator and denominator in \
         the same change",
        fixture.label, measurement.compared, fixture.compared_total
    );
    assert!(
        measurement.matched >= fixture.matched_floor,
        "{} matched-opcode count regressed below the locked floor {}, got {}",
        fixture.label,
        fixture.matched_floor,
        measurement.matched
    );
    assert!(
        measurement.pct >= fixture.floor_pct,
        "{} opcode-equivalence regressed below {}%, got {}%",
        fixture.label,
        fixture.floor_pct,
        measurement.pct
    );
    if let Some(label) = fixture.published_bar {
        let published: f64 = published_value(label);
        assert!(
            f64::from(measurement.pct) >= published,
            "recovery.json publishes {label} at {published}%; this run measured {}%",
            measurement.pct
        );
    }
}

#[test]
fn yarv_recompile_equivalence_is_reproducible() {
    let Some(toolchain): Option<ToolchainBanner> = require_mri_measured_series(GRADED) else {
        return;
    };
    println!("grading {GRADED} against {}", toolchain.banner);

    let mut graded: usize = 0;
    for fixture in &FIXTURES {
        let measurement: Measurement = measure(fixture);
        enforce_floors(fixture, &measurement);
        println!(
            "[{}] matched={} compared={} pct={} floor={}% published_bar={}",
            fixture.label,
            measurement.matched,
            measurement.compared,
            measurement.pct,
            fixture.floor_pct,
            fixture.published_bar.unwrap_or("none")
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        FIXTURES.len(),
        "every fixture in this differential must be measured, not skipped"
    );
}
