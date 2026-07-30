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
             and that text carries no `matches N of M opcodes` phrase for this run to be checked \
             against. This run measured {matched} of {compared}; state it, or the published prose is \
             unverifiable.\n--- detail ---\n{detail}"
        ));
    };
    if (stated_matched, stated_compared) != (matched, compared) {
        return Some(format!(
            "the {label} bar states it matches {stated_matched} of {stated_compared} opcodes and \
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
            "real MRI recompiles the recovered source and the YARV opcode multiset matches {num} of \
             {den} opcodes, which is 98.67%."
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
        "{} original now compiles to {} opcodes, not the {} every pinned count for it was measured \
         against; re-measure this fixture and update the published numerator and denominator in \
         the same change",
        fixture.label, measurement.compared, fixture.compared_total
    );
    assert_eq!(
        measurement.matched, fixture.matched_total,
        "{} matched {} opcodes, not the {} it is pinned to. The inputs are committed and the \
         interpreter series is pinned, so this count does not legitimately move: a lower number is \
         a regression and a higher one is an improvement the published figure has to be updated to \
         describe. Both directions fail here on purpose.",
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
fn yarv_recompile_equivalence_is_reproducible() {
    let Some(toolchain): Option<ToolchainBanner> = require_mri_measured_series(GRADED) else {
        return;
    };
    println!("grading {GRADED} against {}", toolchain.banner);

    let mut graded: usize = 0;
    for fixture in &FIXTURES {
        let measurement: Measurement = measure(fixture);
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
        "every fixture in this differential must be measured, not skipped"
    );
}
