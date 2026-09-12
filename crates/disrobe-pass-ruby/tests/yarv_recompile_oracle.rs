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

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_ruby::analyze_bytes;
use ruby_toolchain::{ToolchainBanner, require_exact_mri_recompile};
use sha2::{Digest, Sha256};

const HELLO_EXPECTED_PCT: u32 = 100;
const GREETER_EXPECTED_PCT: u32 = 100;
const MEGAFILE_EXPECTED_PCT: u32 = 98;

const HELLO_MATCHED_TOTAL: u32 = 4;
const GREETER_MATCHED_TOTAL: u32 = 79;
const MEGAFILE_MATCHED_TOTAL: u32 = 23_648;

const HELLO_COMPARED_TOTAL: u32 = 4;
const GREETER_COMPARED_TOTAL: u32 = 79;
const MEGAFILE_COMPARED_TOTAL: u32 = 23_966;

const PUBLISHED_HEADING: &str = "Ruby YARV";
const PUBLISHED_GREETER_BAR: &str = "greeter";
const PUBLISHED_MEGAFILE_BAR: &str = "megafile";

const GRADED: &str = "the original YARV opcode-name multiset recall after recompiling hello.rb, greeter.rb and \
     megafile/edge_cases.rb";
const EVIDENCE_DIR_VAR: &str = "DISROBE_YARV_EVIDENCE_DIR";
const REPORT_SCHEMA: &str = "disrobe.yarv-opcode-name-multiset-recall.v1";
const REPORT_METRIC: &str = "original opcode-name multiset recall after recompilation";

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
    expected_pct: u32,
    matched_total: u32,
    compared_total: u32,
    published_bar: Option<&'static str>,
}

const FIXTURES: [Fixture; 3] = [
    Fixture {
        label: "hello",
        original_rel: "hello.rb",
        yarvc_rel: "mri/yarv/hello.rb.yarvc",
        expected_pct: HELLO_EXPECTED_PCT,
        matched_total: HELLO_MATCHED_TOTAL,
        compared_total: HELLO_COMPARED_TOTAL,
        published_bar: None,
    },
    Fixture {
        label: "greeter",
        original_rel: "greeter.rb",
        yarvc_rel: "mri/yarv/greeter.rb.yarvc",
        expected_pct: GREETER_EXPECTED_PCT,
        matched_total: GREETER_MATCHED_TOTAL,
        compared_total: GREETER_COMPARED_TOTAL,
        published_bar: Some(PUBLISHED_GREETER_BAR),
    },
    Fixture {
        label: "megafile",
        original_rel: "megafile/edge_cases.rb",
        yarvc_rel: "mri/yarv/edge_cases.rb.yarvc",
        expected_pct: MEGAFILE_EXPECTED_PCT,
        matched_total: MEGAFILE_MATCHED_TOTAL,
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

const PUBLISHED_VALUE_TOLERANCE: f64 = 0.05;

fn published_count_defect(
    bar: &serde_json::Value,
    label: &str,
    measured: &Measurement,
) -> Option<String> {
    let matched: u64 = u64::from(measured.matched);
    let compared: u64 = u64::from(measured.compared);
    let num: Option<u64> = bar.get("num").and_then(serde_json::Value::as_u64);
    let den: Option<u64> = bar.get("den").and_then(serde_json::Value::as_u64);
    match (num, den) {
        (None, None) => Some(format!(
            "the {label} bar publishes no counts at all, so this check compares the run's \
             {matched} of {compared} against nothing and reports success either way; publish the \
             fraction the fixture measures"
        )),
        (Some(num), Some(den)) => (num != matched || den != compared).then(|| {
            format!(
                "the {label} bar publishes the counts {num} of {den}, but this run measured \
                     {matched} of {compared}; re-measure the fixture and publish the counts it \
                     produced, because a published fraction no run reproduces states a recovery \
                     rate nothing measured"
            )
        }),
        (Some(num), None) => Some(format!(
            "the {label} bar publishes the numerator {num} with no `den`, so the fraction it states \
             has no denominator to be read against; this run measured {matched} of {compared}"
        )),
        (None, Some(den)) => Some(format!(
            "the {label} bar publishes the denominator {den} with no `num`, so the fraction it \
             states has no numerator to be read against; this run measured {matched} of {compared}"
        )),
    }
}

fn counts_stated_in_detail(detail: &str) -> Option<(u64, u64)> {
    let at: usize = detail.find("matches ")?;
    let rest: &str = &detail[at + "matches ".len()..];
    let (numerator, tail): (&str, &str) = rest.split_once(" of ")?;
    let denominator: String = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    Some((
        numerator.parse::<u64>().ok()?,
        denominator.parse::<u64>().ok()?,
    ))
}

fn percentage_stated_in_detail(detail: &str) -> Option<f64> {
    let at: usize = detail.find("which is ")?;
    let rest: &str = &detail[at + "which is ".len()..];
    let figure: String = rest
        .chars()
        .take_while(|c: &char| c.is_ascii_digit() || *c == '.')
        .collect::<String>();
    figure.parse::<f64>().ok()
}

fn published_detail_defect(
    bar: &serde_json::Value,
    label: &str,
    measured: &Measurement,
) -> Option<String> {
    let detail: &str = bar["detail"].as_str().unwrap_or_else(|| {
        panic!(
            "the {label} bar must carry the detail text every document renders beside it, because \
             that prose is where its counts are stated"
        )
    });
    let matched: u64 = u64::from(measured.matched);
    let compared: u64 = u64::from(measured.compared);
    let Some((stated_matched, stated_compared)): Option<(u64, u64)> =
        counts_stated_in_detail(detail)
    else {
        return Some(format!(
            "the {label} bar states its counts in its detail text as well as plotting their rate, \
             and that text carries no `matches N of M` phrase for this run to be checked \
             against. This run measured {matched} of {compared}; state it, or the published prose is \
             unverifiable.\n--- detail ---\n{detail}"
        ));
    };
    if (stated_matched, stated_compared) != (matched, compared) {
        return Some(format!(
            "the {label} bar states it matches {stated_matched} of {stated_compared} original \
             opcode-name multiset members and \
             every document renders that sentence, but this run measured {matched} of {compared}; \
             the prose beside a figure has to describe the same run the figure does, so re-measure \
             and restate it.\n--- detail ---\n{detail}"
        ));
    }
    if compared == 0 {
        return Some(format!(
            "the {label} bar states a denominator of zero, over which any numerator reads as \
             anything"
        ));
    }
    let derived: f64 = 100.0 * matched as f64 / compared as f64;
    if let Some(stated) = percentage_stated_in_detail(detail)
        && (stated - derived).abs() >= PUBLISHED_VALUE_TOLERANCE
    {
        return Some(format!(
            "the {label} bar states {stated}% beside its own counts {matched} of {compared}, which \
             are {derived:.2}%\n--- detail ---\n{detail}"
        ));
    }
    None
}

fn published_rate_defect(
    published: f64,
    matched: u32,
    compared: u32,
    label: &str,
    measured_by: &str,
) -> Option<String> {
    if compared == 0 {
        return Some(format!(
            "{label}: the graded population is empty, so no plotted rate over it means anything"
        ));
    }
    if !(0.0..=100.0).contains(&published) {
        return Some(format!(
            "xtask/data/recovery.json plots {label} at {published}, which is not a rate"
        ));
    }
    let rate: f64 = 100.0 * f64::from(matched) / f64::from(compared);
    ((published - rate).abs() >= PUBLISHED_VALUE_TOLERANCE).then(|| {
        format!(
            "xtask/data/recovery.json plots {label} at {published}% and every document renders that \
             number, but {measured_by} is {matched}/{compared} = {rate:.2}%. The bar must equal the \
             measurement, not bound it, so a recovery that drifts in either direction fails here \
             until the figure is updated to describe it."
        )
    })
}

fn published_value_defect(bar: &serde_json::Value, label: &str) -> Option<String> {
    let value: f64 = bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the {label} bar must carry a numeric value"));
    let counts: Option<(u64, u64)> = bar
        .get("num")
        .and_then(serde_json::Value::as_u64)
        .zip(bar.get("den").and_then(serde_json::Value::as_u64));
    let Some((num, den)): Option<(u64, u64)> = counts else {
        return Some(format!(
            "the {label} bar plots {value} with no `num` and `den` beside it. Every check in this \
             file that reads those counts then has nothing to read and passes, so a bar that drops \
             its fraction quietly loses the checks that bind the plotted rate to it: publish the \
             counts this crate pins for the fixture"
        ));
    };
    if den == 0 {
        return Some(format!(
            "the {label} bar publishes a denominator of zero, over which any numerator plots as \
             anything"
        ));
    }
    let derived: f64 = 100.0 * num as f64 / den as f64;
    ((derived - value).abs() >= PUBLISHED_VALUE_TOLERANCE).then(|| {
        format!(
            "the {label} bar plots {value} beside its own counts {num} of {den}, which are \
             {derived:.2}; the number every document renders must be the number its own fraction \
             produces"
        )
    })
}

#[test]
fn published_yarv_bars_match_the_counts_this_crate_pins() {
    let mut checked: usize = 0;
    for fixture in &FIXTURES {
        let Some(label): Option<&'static str> = fixture.published_bar else {
            continue;
        };
        let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
        let value: f64 = published_value(label);
        if let Some(defect) = published_rate_defect(
            value,
            fixture.matched_total,
            fixture.compared_total,
            label,
            "the count this crate pins for the same committed fixture",
        ) {
            panic!("{defect}");
        }
        if let Some(defect) = published_value_defect(&bar, label) {
            panic!("{defect}");
        }
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "both published YARV bars must be checked against the counts this crate pins"
    );
}

#[test]
fn a_published_count_that_no_run_reproduces_is_rejected() {
    let measured: Measurement = Measurement {
        mode: RecompileMode::Whole,
        matched: 23_648,
        compared: MEGAFILE_COMPARED_TOTAL,
        pct: MEGAFILE_EXPECTED_PCT,
    };
    let num: u64 = u64::from(measured.matched);
    let den: u64 = u64::from(measured.compared);
    let agreeing: serde_json::Value = serde_json::json!({"num": num, "den": den});
    assert!(
        published_count_defect(&agreeing, PUBLISHED_MEGAFILE_BAR, &measured).is_none(),
        "counts equal to the measured matched and compared totals must be accepted"
    );
    for disagreeing in [
        serde_json::json!({"num": num + 1, "den": den}),
        serde_json::json!({"num": num - 1, "den": den}),
        serde_json::json!({"num": num, "den": den + 1}),
        serde_json::json!({"num": num}),
        serde_json::json!({"den": den}),
    ] {
        assert!(
            published_count_defect(&disagreeing, PUBLISHED_MEGAFILE_BAR, &measured).is_some(),
            "the counts {disagreeing} state a fraction the run did not produce and must be rejected"
        );
    }
    assert!(
        published_count_defect(&serde_json::json!({}), PUBLISHED_MEGAFILE_BAR, &measured).is_some(),
        "a bar carrying no counts at all used to be accepted here on the argument that its \
         fraction lives in its detail text, but that let both count checks pass by having nothing \
         to read; every plotted YARV bar now publishes the fraction its fixture measures, so an \
         absent pair is a defect rather than a shape"
    );

    let honest: serde_json::Value = serde_json::json!({"num": num, "den": den, "value": 98.67});
    assert!(
        published_value_defect(&honest, PUBLISHED_MEGAFILE_BAR).is_none(),
        "a plotted value equal to its own fraction must be accepted"
    );
    for inconsistent in [
        serde_json::json!({"num": num, "den": den, "value": 100.0}),
        serde_json::json!({"num": num, "den": den, "value": 98.0}),
        serde_json::json!({"num": num, "den": 0, "value": 98.67}),
    ] {
        assert!(
            published_value_defect(&inconsistent, PUBLISHED_MEGAFILE_BAR).is_some(),
            "the bar {inconsistent} plots a number its own counts do not produce and must be \
             rejected"
        );
    }

    let stated: serde_json::Value = serde_json::json!({
        "detail": format!(
            "real MRI recompiles the recovered source and the original YARV opcode-name multiset \
             recall matches {num} of {den} members, which is 98.67%."
        )
    });
    assert!(
        published_detail_defect(&stated, PUBLISHED_MEGAFILE_BAR, &measured).is_none(),
        "detail prose stating exactly the counts this run measured must be accepted"
    );
    for wrong in [
        format!("matches {} of {den} opcodes, which is 98.67%.", num - 48),
        format!("matches {num} of {} opcodes, which is 98.67%.", den - 1),
        format!("matches {num} of {den} opcodes, which is 99.90%."),
        "the recovered source recompiles cleanly.".to_owned(),
    ] {
        let bar: serde_json::Value = serde_json::json!({"detail": wrong});
        assert!(
            published_detail_defect(&bar, PUBLISHED_MEGAFILE_BAR, &measured).is_some(),
            "the detail text {wrong:?} states something this run did not measure and must be \
             rejected; prose stating counts no run produced is the same defect as a plotted number \
             no run produced"
        );
    }
}

#[test]
fn a_plotted_rate_that_does_not_equal_the_measurement_is_rejected_in_both_directions() {
    let matched: u32 = MEGAFILE_MATCHED_TOTAL;
    let compared: u32 = MEGAFILE_COMPARED_TOTAL;
    let truth: f64 = 100.0 * f64::from(matched) / f64::from(compared);
    assert!(
        (truth - 98.67).abs() < PUBLISHED_VALUE_TOLERANCE,
        "the pinned megafile counts are {matched}/{compared}, whose rate is {truth:.4}; the figure \
         this crate expects to be published is 98.67"
    );
    assert!(
        published_rate_defect(98.67, matched, compared, PUBLISHED_MEGAFILE_BAR, "pinned").is_none(),
        "the rate the pinned counts produce must be accepted, otherwise the published figure this \
         crate asks for could never be right"
    );
    for understating in [98.0, 90.0, 0.0] {
        let defect: String = published_rate_defect(
            understating,
            matched,
            compared,
            PUBLISHED_MEGAFILE_BAR,
            "pinned",
        )
        .unwrap_or_else(|| {
            panic!(
                "a plotted {understating}% below the measured {truth:.2}% understates the recovery \
                 and must be rejected; a figure that only bounds the measurement stops describing \
                 it as soon as the recovery improves"
            )
        });
        assert!(
            defect.contains("must equal the measurement, not bound it"),
            "the rejection must say why a bound is not enough, got: {defect}"
        );
    }
    for overstating in [98.9, 100.0] {
        assert!(
            published_rate_defect(
                overstating,
                matched,
                compared,
                PUBLISHED_MEGAFILE_BAR,
                "pinned"
            )
            .is_some(),
            "a plotted {overstating}% above the measured {truth:.2}% overstates the recovery and \
             must be rejected"
        );
    }
    assert!(
        published_rate_defect(100.0, 0, 0, PUBLISHED_MEGAFILE_BAR, "pinned").is_some(),
        "a rate over an empty population must be rejected rather than dividing by zero"
    );
    assert!(
        published_rate_defect(101.0, matched, compared, PUBLISHED_MEGAFILE_BAR, "pinned").is_some(),
        "a figure outside 0 to 100 is not a rate"
    );
    assert!(
        published_rate_defect(
            100.0,
            GREETER_MATCHED_TOTAL,
            GREETER_COMPARED_TOTAL,
            PUBLISHED_GREETER_BAR,
            "pinned"
        )
        .is_none(),
        "an exact fixture legitimately plots 100, so the check must not reject a true 100"
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

fn evidence_run_dir() -> PathBuf {
    let raw: OsString = std::env::var_os(EVIDENCE_DIR_VAR).unwrap_or_else(|| {
        panic!(
            "{EVIDENCE_DIR_VAR} must name a new absolute directory whose parent already exists; \
             the required YARV measurement retains its evidence and cannot use disposable test \
             output"
        )
    });
    let path: PathBuf = PathBuf::from(raw);
    assert!(
        path.is_absolute(),
        "{EVIDENCE_DIR_VAR} must be absolute, got {}",
        path.display()
    );
    assert!(
        !path.exists(),
        "{EVIDENCE_DIR_VAR} points to {}, which already exists; evidence runs refuse directory \
         reuse so an earlier report cannot be mistaken for this run",
        path.display()
    );
    let parent: &Path = path.parent().unwrap_or_else(|| {
        panic!(
            "{EVIDENCE_DIR_VAR} has no parent directory: {}",
            path.display()
        )
    });
    assert!(
        parent.is_dir(),
        "the parent of {EVIDENCE_DIR_VAR} must already exist so the caller owns the durable \
         location, got {}",
        parent.display()
    );

    let mut target_roots: Vec<PathBuf> = Vec::new();
    if let Some(raw_target) = std::env::var_os("CARGO_TARGET_DIR") {
        let target: PathBuf = PathBuf::from(raw_target);
        target_roots.push(if target.is_absolute() {
            target
        } else {
            std::env::current_dir()
                .expect("read current directory")
                .join(target)
        });
    }
    let mut repository_target: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    repository_target.pop();
    repository_target.pop();
    repository_target.push("target");
    target_roots.push(repository_target);
    assert!(
        target_roots
            .iter()
            .all(|target: &PathBuf| !path.starts_with(target)),
        "{EVIDENCE_DIR_VAR} must be outside every Cargo target, got {}",
        path.display()
    );
    assert!(
        !parent.ancestors().any(|ancestor: &Path| {
            ancestor.join(".rustc_info.json").is_file() || ancestor.join("CACHEDIR.TAG").is_file()
        }),
        "{EVIDENCE_DIR_VAR} must be outside Cargo build output, got {}",
        path.display()
    );

    std::fs::create_dir(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "create the unique evidence directory {}: {error}",
            path.display()
        )
    });
    path
}

fn report_string<'a>(report: &'a serde_json::Value, pointer: &str) -> Result<&'a str, String> {
    report
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("the evidence report is missing string field {pointer}"))
}

fn report_u64(report: &serde_json::Value, pointer: &str) -> Result<u64, String> {
    report
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("the evidence report is missing integer field {pointer}"))
}

fn recorded_sha256<'a>(value: &'a serde_json::Value, label: &str) -> Result<&'a str, String> {
    let sha256: &str = value
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{label} carries no SHA-256"))?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} carries invalid SHA-256 `{sha256}`"));
    }
    Ok(sha256)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes: Vec<u8> = std::fs::read(path)
        .map_err(|error: std::io::Error| format!("read {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_artifact(
    value: &serde_json::Value,
    label: &str,
    required_parent: Option<&Path>,
) -> Result<PathBuf, String> {
    let expected_sha256: &str = recorded_sha256(value, label)?;
    let path: PathBuf = PathBuf::from(
        value
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{label} carries no path"))?,
    );
    if let Some(parent) = required_parent
        && !path.starts_with(parent)
    {
        return Err(format!(
            "{label} escaped the evidence directory: {}",
            path.display()
        ));
    }
    let metadata: std::fs::Metadata = std::fs::metadata(&path)
        .map_err(|error: std::io::Error| format!("read {label} {}: {error}", path.display()))?;
    let stated_size: u64 = value
        .get("size_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{label} carries no byte size"))?;
    if metadata.len() != stated_size {
        return Err(format!(
            "{label} states {stated_size} bytes but {} has {}",
            path.display(),
            metadata.len()
        ));
    }
    let actual_sha256: String = sha256_file(&path)?;
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "{label} records SHA-256 {expected_sha256}, but {} now hashes to {actual_sha256}",
            path.display()
        ));
    }
    Ok(path)
}

fn validate_expected_artifact(
    value: &serde_json::Value,
    label: &str,
    expected_path: &Path,
) -> Result<(), String> {
    let reported_path: PathBuf = validate_artifact(value, label, None)?;
    let reported: PathBuf = std::fs::canonicalize(&reported_path).map_err(|error| {
        format!(
            "resolve reported {label} path {}: {error}",
            reported_path.display()
        )
    })?;
    let expected: PathBuf = std::fs::canonicalize(expected_path).map_err(|error| {
        format!(
            "resolve expected {label} path {}: {error}",
            expected_path.display()
        )
    })?;
    if reported != expected {
        return Err(format!(
            "the report binds {label} to {}, but this run used {}",
            reported.display(),
            expected.display()
        ));
    }
    Ok(())
}

fn validate_distribution(
    report: &serde_json::Value,
    measurement: &Measurement,
) -> Result<(), String> {
    let rows: &[serde_json::Value] = report
        .get("per_opcode")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "the evidence report carries no per-opcode distribution".to_owned())?;
    if rows.is_empty() {
        return Err("the evidence report carries an empty per-opcode distribution".to_owned());
    }

    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut original_total: u64 = 0;
    let mut recovered_total: u64 = 0;
    let mut matched_total: u64 = 0;
    let mut deficit_total: u64 = 0;
    let mut excess_total: u64 = 0;
    for row in rows {
        let opcode: &str = row
            .get("opcode")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "a per-opcode row has no opcode name".to_owned())?;
        if opcode.is_empty() || !names.insert(opcode) {
            return Err(format!("invalid or duplicate opcode name `{opcode}`"));
        }
        if previous.is_some_and(|prior: &str| prior >= opcode) {
            return Err(format!(
                "per-opcode rows are not strictly sorted at `{opcode}`"
            ));
        }
        previous = Some(opcode);
        let number = |field: &str| -> Result<u64, String> {
            row.get(field)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("opcode `{opcode}` has no integer `{field}` count"))
        };
        let original: u64 = number("original")?;
        let recovered: u64 = number("recovered")?;
        let matched: u64 = number("matched")?;
        let deficit: u64 = number("deficit")?;
        let excess: u64 = number("excess")?;
        let expected_matched: u64 = original.min(recovered);
        if matched != expected_matched
            || deficit != original - expected_matched
            || excess != recovered - expected_matched
        {
            return Err(format!(
                "opcode `{opcode}` does not satisfy matched=min(original,recovered), deficit=original-matched and excess=recovered-matched"
            ));
        }
        original_total += original;
        recovered_total += recovered;
        matched_total += matched;
        deficit_total += deficit;
        excess_total += excess;
    }

    let totals: [(&str, u64); 5] = [
        ("original", original_total),
        ("recovered", recovered_total),
        ("matched", matched_total),
        ("deficit", deficit_total),
        ("excess", excess_total),
    ];
    for (field, calculated) in totals {
        let stated: u64 = report_u64(report, &format!("/totals/{field}"))?;
        if stated != calculated {
            return Err(format!(
                "the report states {field}={stated}, but its per-opcode rows sum to {calculated}"
            ));
        }
    }
    if original_total != u64::from(measurement.compared)
        || matched_total != u64::from(measurement.matched)
        || deficit_total != original_total - matched_total
        || excess_total != recovered_total - matched_total
    {
        return Err(format!(
            "the per-opcode distribution does not reproduce the summary matched={}/{}",
            measurement.matched, measurement.compared
        ));
    }
    let stated_pct: u64 = report_u64(report, "/totals/recall_pct_integer")?;
    if stated_pct != u64::from(measurement.pct) {
        return Err(format!(
            "the report states integer recall {stated_pct}, but stdout states {}",
            measurement.pct
        ));
    }
    Ok(())
}

fn validate_evidence_report(
    evidence_dir: &Path,
    fixture: &Fixture,
    recovered_source: &str,
    measurement: &Measurement,
    toolchain: &ToolchainBanner,
) -> Result<(), String> {
    let report_path: PathBuf = evidence_dir.join("report.json");
    let raw: String = std::fs::read_to_string(&report_path)
        .map_err(|error: std::io::Error| format!("read {}: {error}", report_path.display()))?;
    let report: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error: serde_json::Error| format!("parse {}: {error}", report_path.display()))?;
    if report_string(&report, "/schema")? != REPORT_SCHEMA
        || report_string(&report, "/metric")? != REPORT_METRIC
        || report
            .get("compile_only")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err("the evidence report does not identify the compile-only opcode-name multiset recall metric".to_owned());
    }
    let limitations: BTreeSet<&str> = report
        .get("limitations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "the evidence report carries no metric limitations".to_owned())?
        .iter()
        .map(|value: &serde_json::Value| {
            value
                .as_str()
                .ok_or_else(|| "a metric limitation is not text".to_owned())
        })
        .collect::<Result<BTreeSet<&str>, String>>()?;
    let required_limitations: BTreeSet<&str> = [
        "instruction ordering is not compared",
        "instruction operands are not compared",
        "control flow is not compared",
        "extra recovered instructions do not reduce recall",
    ]
    .into_iter()
    .collect();
    if limitations != required_limitations {
        return Err(format!(
            "the evidence report states the wrong metric limitations: {limitations:?}"
        ));
    }
    let reported_mode: &str = report_string(&report, "/mode")?;
    let expected_mode: &str = match measurement.mode {
        RecompileMode::Whole => "whole",
        RecompileMode::Partial => "partial",
    };
    if reported_mode != expected_mode {
        return Err(format!(
            "the report mode `{reported_mode}` disagrees with stdout mode `{expected_mode}`"
        ));
    }
    if report_string(&report, "/runtime/version")? != toolchain.banner {
        return Err("the retained Ruby version disagrees with the executable preflight".to_owned());
    }
    validate_artifact(&report["runtime"]["executable"], "Ruby executable", None)?;
    validate_artifact(
        &report["runtime"]["shared_library"],
        "Ruby shared runtime library",
        None,
    )?;
    for (field, expected) in [
        ("fixture_source", corpus_path(fixture.original_rel)),
        ("fixture_ibf", corpus_path(fixture.yarvc_rel)),
        ("ruby_harness", corpus_path("mri/yarv/recompile_oracle.rb")),
        (
            "rust_harness",
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/yarv_recompile_oracle.rs"),
        ),
    ] {
        validate_expected_artifact(&report["inputs"][field], field, &expected)?;
    }
    let original_copy: PathBuf = validate_artifact(
        &report["stored"]["original_source"],
        "retained original source",
        Some(evidence_dir),
    )?;
    let recovered_copy: PathBuf = validate_artifact(
        &report["stored"]["recovered_source"],
        "retained recovered source",
        Some(evidence_dir),
    )?;
    let compiled_recovered_copy: PathBuf = validate_artifact(
        &report["stored"]["compiled_recovered_source"],
        "retained compiled recovered source",
        Some(evidence_dir),
    )?;
    let original_disassembly: PathBuf = validate_artifact(
        &report["stored"]["original_disassembly"],
        "retained original disassembly",
        Some(evidence_dir),
    )?;
    let recovered_disassembly: PathBuf = validate_artifact(
        &report["stored"]["recovered_disassembly"],
        "retained recovered disassembly",
        Some(evidence_dir),
    )?;
    let original_stream: PathBuf = validate_artifact(
        &report["stored"]["original_opcode_stream"],
        "retained original opcode stream",
        Some(evidence_dir),
    )?;
    let recovered_stream: PathBuf = validate_artifact(
        &report["stored"]["recovered_opcode_stream"],
        "retained recovered opcode stream",
        Some(evidence_dir),
    )?;
    if std::fs::read(&original_copy).map_err(|error| error.to_string())?
        != std::fs::read(corpus_path(fixture.original_rel)).map_err(|error| error.to_string())?
        || std::fs::read_to_string(&recovered_copy).map_err(|error| error.to_string())?
            != recovered_source
    {
        return Err("the retained source files differ from the graded inputs".to_owned());
    }
    if std::fs::metadata(compiled_recovered_copy)
        .map_err(|error| error.to_string())?
        .len()
        == 0
    {
        return Err("the exact recovered source passed to Ruby is empty".to_owned());
    }
    if std::fs::read_to_string(&original_stream)
        .map_err(|error| error.to_string())?
        .lines()
        .count()
        != measurement.compared as usize
    {
        return Err("the retained original opcode stream has the wrong length".to_owned());
    }
    let recovered_stream_count: usize = std::fs::read_to_string(&recovered_stream)
        .map_err(|error| error.to_string())?
        .lines()
        .count();
    if recovered_stream_count != report_u64(&report, "/totals/recovered")? as usize {
        return Err("the retained recovered opcode stream has the wrong length".to_owned());
    }
    if std::fs::metadata(original_disassembly)
        .map_err(|error| error.to_string())?
        .len()
        == 0
        || std::fs::metadata(recovered_disassembly)
            .map_err(|error| error.to_string())?
            .len()
            == 0
    {
        return Err("a retained raw disassembly stream is empty".to_owned());
    }
    validate_distribution(&report, measurement)
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

fn measure(fixture: &Fixture, run_dir: &Path, toolchain: &ToolchainBanner) -> Measurement {
    let recovered: String = recover_source(fixture.yarvc_rel);
    let recovered_path: PathBuf = run_dir.join(format!("{}.recovered.rb", fixture.label));
    std::fs::write(&recovered_path, &recovered)
        .unwrap_or_else(|e: std::io::Error| panic!("write recovered {}: {e}", fixture.label));

    let oracle: PathBuf = corpus_path("mri/yarv/recompile_oracle.rb");
    let original: PathBuf = corpus_path(fixture.original_rel);
    let fixture_path: PathBuf = corpus_path(fixture.yarvc_rel);
    let rust_harness: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("yarv_recompile_oracle.rs");
    let fixture_evidence_dir: PathBuf = run_dir.join(fixture.label);
    let output = Command::new(&toolchain.executable)
        .arg(&oracle)
        .arg(&original)
        .arg(&recovered_path)
        .arg(&fixture_path)
        .arg(&rust_harness)
        .arg(&fixture_evidence_dir)
        .output()
        .unwrap_or_else(|e: std::io::Error| {
            panic!(
                "ruby was usable a moment ago but could not run {} for {}: {e}",
                oracle.display(),
                fixture.label
            )
        });
    assert!(
        output.status.success(),
        "the compile-only Ruby harness failed for {} with {}: {}",
        fixture.label,
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
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
        line.contains("compile_only=true") && line.contains("metric=opcode-name-multiset-recall"),
        "the {} run did not identify its result as compile-only opcode-name multiset recall: \
         `{line}`",
        fixture.label
    );
    assert!(
        measurement.compared > 0,
        "the {} original compiled to zero opcode-name multiset members, so any percentage over it \
         would be vacuous",
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
    validate_evidence_report(
        &fixture_evidence_dir,
        fixture,
        &recovered,
        &measurement,
        toolchain,
    )
    .unwrap_or_else(|defect: String| {
        panic!(
            "the retained evidence for {} is incomplete or inconsistent: {defect}",
            fixture.label
        )
    });
    measurement
}

fn enforce_pinned_measurement(fixture: &Fixture, measurement: &Measurement) {
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
        "{} original now compiles to {} opcode-name multiset members, not the {} every pinned \
         count for it was measured against; re-measure this fixture and update the published \
         numerator and denominator in the same change",
        fixture.label, measurement.compared, fixture.compared_total
    );
    assert_eq!(
        measurement.matched, fixture.matched_total,
        "{} matched {} original opcode-name multiset members, not the {} it is pinned to. The \
         inputs are committed and the interpreter patch release is pinned, so this count does not \
         legitimately move: a lower number is a regression and a higher one is an improvement the \
         published figure has to be updated to describe. Both directions fail here on purpose.",
        fixture.label, measurement.matched, fixture.matched_total
    );
    assert_eq!(
        measurement.pct, fixture.expected_pct,
        "{} scored {}%, not the {}% it is pinned to",
        fixture.label, measurement.pct, fixture.expected_pct
    );
    if let Some(label) = fixture.published_bar {
        let published: f64 = published_value(label);
        if let Some(defect) = published_rate_defect(
            published,
            measurement.matched,
            measurement.compared,
            label,
            "what this run measured",
        ) {
            panic!("{defect}");
        }
        let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, label);
        if let Some(defect) = published_count_defect(&bar, label, measurement) {
            panic!("{defect}");
        }
        if let Some(defect) = published_detail_defect(&bar, label, measurement) {
            panic!("{defect}");
        }
    }
}

#[test]
fn artifact_validation_rejects_same_size_mutation_and_wrong_path() {
    let (expected_file, mut expected_sink): (ScratchFile, std::fs::File) =
        ScratchFile::create("yarv_evidence_expected", "bin")
            .unwrap_or_else(|error| panic!("create expected artifact: {error}"));
    expected_sink
        .write_all(b"alpha")
        .unwrap_or_else(|error| panic!("write expected artifact: {error}"));
    drop(expected_sink);
    let expected_path: &Path = expected_file.path();
    let original_hash: String = sha256_file(expected_path)
        .unwrap_or_else(|error| panic!("hash expected artifact: {error}"));
    let recorded: serde_json::Value = serde_json::json!({
        "path": expected_path,
        "size_bytes": 5,
        "sha256": original_hash
    });
    validate_artifact(&recorded, "benign test artifact", None)
        .unwrap_or_else(|error| panic!("validate unchanged test artifact: {error}"));

    std::fs::write(expected_path, b"omega")
        .unwrap_or_else(|error| panic!("mutate expected artifact: {error}"));
    assert!(
        validate_artifact(&recorded, "benign test artifact", None)
            .is_err_and(|defect: String| defect.contains("now hashes to")),
        "the validator must reject changed bytes even when the file size is unchanged"
    );

    let (other_file, mut other_sink): (ScratchFile, std::fs::File) =
        ScratchFile::create("yarv_evidence_other", "bin")
            .unwrap_or_else(|error| panic!("create other artifact: {error}"));
    other_sink
        .write_all(b"alpha")
        .unwrap_or_else(|error| panic!("write other artifact: {error}"));
    drop(other_sink);
    let other_hash: String = sha256_file(other_file.path())
        .unwrap_or_else(|error| panic!("hash other artifact: {error}"));
    let wrong_path: serde_json::Value = serde_json::json!({
        "path": other_file.path(),
        "size_bytes": 5,
        "sha256": other_hash
    });
    assert!(
        validate_expected_artifact(&wrong_path, "benign test artifact", expected_path)
            .is_err_and(|defect: String| defect.contains("but this run used")),
        "a valid artifact at a different path must not satisfy an input binding"
    );
}

#[test]
fn distribution_validation_rejects_a_false_opcode_match() {
    let measurement: Measurement = Measurement {
        mode: RecompileMode::Whole,
        matched: 3,
        compared: 4,
        pct: 75,
    };
    let valid: serde_json::Value = serde_json::json!({
        "per_opcode": [
            {"opcode": "leave", "original": 1, "recovered": 1, "matched": 1, "deficit": 0, "excess": 0},
            {"opcode": "putobject", "original": 3, "recovered": 2, "matched": 2, "deficit": 1, "excess": 0}
        ],
        "totals": {
            "original": 4,
            "recovered": 3,
            "matched": 3,
            "deficit": 1,
            "excess": 0,
            "recall_pct_integer": 75
        }
    });
    validate_distribution(&valid, &measurement).unwrap_or_else(|defect: String| {
        panic!("a consistent benign distribution failed: {defect}")
    });

    let mut false_match: serde_json::Value = valid;
    false_match["per_opcode"][1]["matched"] = serde_json::json!(3);
    assert!(
        validate_distribution(&false_match, &measurement)
            .is_err_and(|defect: String| defect.contains("matched=min")),
        "the report validator must reject an opcode count that exceeds the multiset intersection"
    );
}

#[test]
fn yarv_opcode_name_multiset_recall_is_reproducible() {
    let toolchain: ToolchainBanner = require_exact_mri_recompile(GRADED);
    println!("grading {GRADED} against {}", toolchain.banner);
    let run_dir: PathBuf = evidence_run_dir();

    let mut graded: usize = 0;
    for fixture in &FIXTURES {
        let measurement: Measurement = measure(fixture, &run_dir, &toolchain);
        enforce_pinned_measurement(fixture, &measurement);
        println!(
            "[{}] matched={} compared={} pct={} pinned={}% published_bar={}",
            fixture.label,
            measurement.matched,
            measurement.compared,
            measurement.pct,
            fixture.expected_pct,
            fixture.published_bar.unwrap_or("none")
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        FIXTURES.len(),
        "every fixture in this recall measurement must be measured, not skipped"
    );
    println!("retained compile-only evidence in {}", run_dir.display());
}
