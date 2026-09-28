#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_pickle::{
    Disassembly, Finding, SafetyReport, Severity, VmTrace, analyze_all, analyze_polyglot,
    analyze_safety, disassemble, execute,
};
use serde_json::Value;

const PYTHON_OVERRIDE_VAR: &str = "DISROBE_PYTHON";
const HARNESS: &str = "find_class_harness.py";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Graded(Severity),
    Refused,
}

#[derive(Debug, Clone, Copy)]
struct Expectation {
    file: &'static str,
    verdict: Verdict,
    finding: Option<&'static str>,
    polyglot: bool,
}

const fn graded(file: &'static str, severity: Severity) -> Expectation {
    Expectation {
        file,
        verdict: Verdict::Graded(severity),
        finding: None,
        polyglot: false,
    }
}

const EXPECTATIONS: [Expectation; 14] = [
    graded("stacked_streams.pkl", Severity::OvertlyMalicious),
    graded("stacked_protocol0_stream.pkl", Severity::OvertlyMalicious),
    graded("nested_global_first.pkl", Severity::OvertlyMalicious),
    graded("nested_unicode_first.pkl", Severity::OvertlyMalicious),
    graded("call_os_execl.pkl", Severity::OvertlyMalicious),
    graded("call_os_spawnlp.pkl", Severity::OvertlyMalicious),
    graded("call_os_posix_spawn.pkl", Severity::OvertlyMalicious),
    graded("call_os_startfile.pkl", Severity::OvertlyMalicious),
    graded("call_urllib_request_urlopen.pkl", Severity::Suspicious),
    graded("call_timeit_timeit.pkl", Severity::OvertlyMalicious),
    graded("call_cprofile_run.pkl", Severity::OvertlyMalicious),
    graded("call_pdb_run.pkl", Severity::OvertlyMalicious),
    Expectation {
        file: "pickle_then_zip.pkl",
        verdict: Verdict::Graded(Severity::Suspicious),
        finding: Some("stream.trailing_bytes"),
        polyglot: true,
    },
    Expectation {
        file: "zip_then_pickle.zip",
        verdict: Verdict::Refused,
        finding: None,
        polyglot: true,
    },
];

const BENIGN_CORPUS_DIRS: [&str; 2] = ["benign", "structural"];
const BENIGN_CORPUS_FIXTURES: usize = 96;
const BENIGN_CORPUS_FALSE_POSITIVES: usize = 52;
const MEMO_UNUSED_STEMS: [&str; 8] = [
    "bytes",
    "frozenset",
    "instance",
    "list",
    "nested_dict",
    "set",
    "str",
    "tuple",
];
const STRUCTURAL_MEMO_UNUSED_STEMS: [&str; 4] =
    ["cyclic_dict", "deep_nested", "oob_buffer", "shared_ref"];
const COPYREG_RECONSTRUCTOR_PROTOCOLS: [u8; 2] = [0, 1];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Truth {
    requested: BTreeSet<String>,
    loaded: usize,
    zip_members: Vec<String>,
}

#[derive(Debug, Clone)]
struct Observed {
    verdict: Result<SafetyReport, String>,
    polyglot: bool,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fail_closed")
}

fn probe(exe: &str) -> bool {
    Command::new(exe)
        .arg("--version")
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

fn demand_python() -> String {
    if let Ok(explicit) = std::env::var(PYTHON_OVERRIDE_VAR)
        && probe(&explicit)
    {
        return explicit;
    }
    let found: Option<&str> = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| probe(candidate));
    let Some(python): Option<&str> = found else {
        panic!(
            "the fail-closed pickle fixtures are graded against CPython's own unpickler through \
             {HARNESS}, and no CPython 3.11 or newer is usable here; install it on PATH or point \
             {PYTHON_OVERRIDE_VAR} at one"
        );
    };
    python.to_owned()
}

fn string_list(value: &Value, what: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{what} is not a list: {value}"))
        .iter()
        .map(|item: &Value| {
            item.as_str()
                .unwrap_or_else(|| panic!("{what} holds a non-string: {item}"))
                .to_owned()
        })
        .collect()
}

fn successful_loads(entry: &Value, key: &str) -> usize {
    entry[key]
        .as_array()
        .unwrap_or_else(|| panic!("harness entry has no {key} list: {entry}"))
        .iter()
        .filter(|load: &&Value| load.get("error").is_none_or(Value::is_null))
        .count()
}

fn run_harness() -> BTreeMap<String, Truth> {
    let python: String = demand_python();
    let dir: PathBuf = fixture_dir();
    let output: Output = Command::new(&python)
        .arg(dir.join(HARNESS))
        .arg(&dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap_or_else(|e| panic!("run {python} {HARNESS}: {e}"));
    assert!(
        output.status.success(),
        "{HARNESS} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("harness prints JSON");
    let entries: &serde_json::Map<String, Value> =
        report.as_object().expect("harness report is an object");
    entries
        .iter()
        .map(|(file, entry): (&String, &Value)| {
            let requested: BTreeSet<String> = string_list(&entry["requested"], "requested")
                .into_iter()
                .collect();
            let zip_members: Vec<String> = if entry["zip_members"].is_null() {
                Vec::new()
            } else {
                string_list(&entry["zip_members"], "zip_members")
            };
            let loaded: usize = successful_loads(entry, "streams")
                + successful_loads(entry, "declared")
                + successful_loads(entry, "nested");
            (
                file.clone(),
                Truth {
                    requested,
                    loaded,
                    zip_members,
                },
            )
        })
        .collect()
}

fn observe(bytes: &[u8]) -> Observed {
    Observed {
        verdict: analyze_all(bytes)
            .map(|(_, _, report): (Disassembly, VmTrace, SafetyReport)| report)
            .map_err(|e: disrobe_pass_pickle::Error| e.to_string()),
        polyglot: analyze_polyglot(bytes).is_polyglot,
    }
}

fn defects(expect: &Expectation, truth: &Truth, observed: &Observed) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let file: &str = expect.file;
    if truth.loaded == 0 {
        found.push(format!(
            "{file}: CPython loads no pickle from it, so it tests nothing"
        ));
    }
    match (expect.verdict, &observed.verdict) {
        (Verdict::Graded(severity), Ok(report)) => {
            if report.severity != severity {
                found.push(format!(
                    "{file}: graded {:?}, expected {severity:?}",
                    report.severity
                ));
            }
            let imports: BTreeSet<String> = report.imports.iter().cloned().collect();
            if imports != truth.requested {
                found.push(format!(
                    "{file}: disrobe sees callables {imports:?}, CPython's unpickler requests {:?}",
                    truth.requested
                ));
            }
            if let Some(category) = expect.finding
                && !report
                    .findings
                    .iter()
                    .any(|f: &Finding| f.category == category)
            {
                found.push(format!("{file}: no {category} finding"));
            }
        }
        (Verdict::Graded(severity), Err(error)) => found.push(format!(
            "{file}: refused ({error}), expected a {severity:?} verdict"
        )),
        (Verdict::Refused, Ok(report)) => found.push(format!(
            "{file}: graded {:?}, expected a refusal",
            report.severity
        )),
        (Verdict::Refused, Err(_)) => {}
    }
    if observed.polyglot != expect.polyglot {
        found.push(format!(
            "{file}: polyglot flag {}, expected {}",
            observed.polyglot, expect.polyglot
        ));
    }
    if expect.polyglot && truth.zip_members.is_empty() {
        found.push(format!("{file}: CPython's zipfile does not open it"));
    }
    found
}

fn read_fixture(file: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_regression_fixture_fails_closed_against_the_find_class_reference() {
    let truths: BTreeMap<String, Truth> = run_harness();
    let expected_files: BTreeSet<&str> =
        EXPECTATIONS.iter().map(|e: &Expectation| e.file).collect();
    let graded_files: BTreeSet<&str> = truths.keys().map(String::as_str).collect();
    assert_eq!(
        graded_files, expected_files,
        "provenance.toml and the expectation table must name the same fixtures"
    );
    let mut all: Vec<String> = Vec::new();
    for expect in &EXPECTATIONS {
        let truth: &Truth = &truths[expect.file];
        all.extend(defects(expect, truth, &observe(&read_fixture(expect.file))));
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn no_regression_fixture_is_expected_benign() {
    for expect in &EXPECTATIONS {
        assert_ne!(
            expect.verdict,
            Verdict::Graded(Severity::Benign),
            "{} would pass while grading Benign",
            expect.file
        );
        assert!(
            expect.polyglot || expect.verdict != Verdict::Refused,
            "{} would pass on a refusal alone",
            expect.file
        );
    }
}

fn correct_stacked_report() -> SafetyReport {
    SafetyReport {
        severity: Severity::OvertlyMalicious,
        findings: Vec::new(),
        imports: vec!["os.system".to_owned()],
        reduce_count: 1,
        unused_memo_count: 0,
    }
}

fn stacked_truth() -> Truth {
    Truth {
        requested: BTreeSet::from(["os.system".to_owned()]),
        loaded: 2,
        zip_members: Vec::new(),
    }
}

#[test]
fn mutation_control_a_first_stream_verdict_is_rejected() {
    let bytes: Vec<u8> = read_fixture("stacked_streams.pkl");
    let first_only: SafetyReport =
        analyze_safety(&execute(&disassemble(&bytes).expect("disasm")).expect("vm"));
    assert_eq!(first_only.severity, Severity::Benign);
    let observed: Observed = Observed {
        verdict: Ok(first_only),
        polyglot: false,
    };
    let found: Vec<String> = defects(&EXPECTATIONS[0], &stacked_truth(), &observed);
    assert!(
        found.iter().any(|d: &String| d.contains("graded Benign")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|d: &String| d.contains("requests")),
        "{found:?}"
    );
}

#[test]
fn mutation_control_a_missed_callable_or_polyglot_is_rejected() {
    let correct: Observed = Observed {
        verdict: Ok(correct_stacked_report()),
        polyglot: false,
    };
    assert!(defects(&EXPECTATIONS[0], &stacked_truth(), &correct).is_empty());
    let mut truth: Truth = stacked_truth();
    truth.requested.insert("builtins.eval".to_owned());
    let found: Vec<String> = defects(&EXPECTATIONS[0], &truth, &correct);
    assert_eq!(found.len(), 1, "{found:?}");

    let trailing: &Expectation = &EXPECTATIONS[12];
    let empty_truth: Truth = Truth {
        requested: BTreeSet::new(),
        loaded: 1,
        zip_members: vec!["data/weights.txt".to_owned()],
    };
    let memo_only: Observed = Observed {
        verdict: Ok(SafetyReport {
            severity: Severity::Suspicious,
            findings: Vec::new(),
            imports: Vec::new(),
            reduce_count: 0,
            unused_memo_count: 1,
        }),
        polyglot: true,
    };
    let found: Vec<String> = defects(trailing, &empty_truth, &memo_only);
    assert_eq!(
        found,
        ["pickle_then_zip.pkl: no stream.trailing_bytes finding"]
    );

    let zip_first: &Expectation = &EXPECTATIONS[13];
    let polyglot_truth: Truth = Truth {
        requested: BTreeSet::from(["os.system".to_owned()]),
        loaded: 1,
        zip_members: vec!["config.json".to_owned()],
    };
    let unflagged: Observed = Observed {
        verdict: Err("pickle disasm".to_owned()),
        polyglot: false,
    };
    assert_eq!(defects(zip_first, &polyglot_truth, &unflagged).len(), 1);
    let not_a_zip: Truth = Truth {
        zip_members: Vec::new(),
        ..polyglot_truth
    };
    let flagged: Observed = Observed {
        verdict: Err("pickle disasm".to_owned()),
        polyglot: true,
    };
    assert_eq!(defects(zip_first, &not_a_zip, &flagged).len(), 1);
}

fn collect_pkl(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries: std::fs::ReadDir =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path: PathBuf = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_pkl(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "pkl") {
            out.push(path);
        }
    }
}

#[test]
fn the_benign_corpus_keeps_its_verdicts() {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("pickle");
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in BENIGN_CORPUS_DIRS {
        collect_pkl(&root.join(dir), &mut files);
    }
    files.sort();
    assert_eq!(files.len(), BENIGN_CORPUS_FIXTURES, "benign corpus size");
    let mut not_benign: Vec<String> = Vec::new();
    for file in &files {
        let bytes: Vec<u8> = std::fs::read(file).expect("read corpus fixture");
        let name: String = file
            .strip_prefix(&root)
            .expect("under corpus root")
            .to_string_lossy()
            .replace('\\', "/");
        match analyze_all(&bytes) {
            Ok((_, _, report)) if report.severity == Severity::Benign => {}
            Ok((_, _, report)) => {
                let categories: BTreeSet<&str> = report
                    .findings
                    .iter()
                    .filter(|f: &&Finding| f.severity != Severity::Benign)
                    .map(|f: &Finding| f.category.as_str())
                    .collect();
                let joined: String = categories.into_iter().collect::<Vec<&str>>().join("+");
                not_benign.push(format!("{name}: {:?} {joined}", report.severity));
            }
            Err(error) => not_benign.push(format!("{name}: refused ({error})")),
        }
    }
    not_benign.sort();
    assert_eq!(
        not_benign,
        expected_false_positives(),
        "benign corpus verdicts"
    );
    assert_eq!(not_benign.len(), BENIGN_CORPUS_FALSE_POSITIVES);
}

fn expected_false_positives() -> Vec<String> {
    let mut expected: Vec<String> = Vec::new();
    for protocol in 0u8..=5 {
        for stem in MEMO_UNUSED_STEMS {
            let categories: &str =
                if stem == "instance" && COPYREG_RECONSTRUCTOR_PROTOCOLS.contains(&protocol) {
                    "global.suspicious_callable+memo.unused"
                } else {
                    "memo.unused"
                };
            expected.push(format!(
                "benign/p{protocol}/{stem}.pkl: Suspicious {categories}"
            ));
        }
    }
    for stem in STRUCTURAL_MEMO_UNUSED_STEMS {
        expected.push(format!("structural/{stem}.pkl: Suspicious memo.unused"));
    }
    expected.sort();
    expected
}
