#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use common::band_gate::{CPYTHON_314, assert_measurement_is_comparable, resolve_band_interpreter};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::stdlib_measure::{
    HarnessRun, MEASURE_HARNESS, Measurement, PINNED_POPULATION, PublishedBar, bar_disagreements,
    find_disrobe, interpreter_stdlib, interpreter_version, manifest_dir, parse_measurement,
    population_line, published_bar, recovery_document, run_measure_with_ledger, workspace_target,
};

const PINNED_MODULES: &str = "tests/harness/pinned_modules_314.txt";

const BAND_CPYTHON: &str = CPYTHON_314.release;
const GRADED: &str = "the published pinned-corpus per-code-object figure";

const OBJECT_PCT_FLOOR: f64 = 96.59;
const MODULES_EXACT_FLOOR: u64 = 122;
const MODULES_EXACT_PCT_FLOOR: f64 = 61.0;
const PINNED_MODULE_COUNT: u64 = 200;

const PINNED_BAR_LABEL: &str = "200-module pinned corpus";

#[test]
fn published_pinned_bar_agrees_with_the_enforced_floor() {
    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let disagreements: Vec<String> = bar_disagreements(&bar, OBJECT_PCT_FLOOR);
    assert!(
        disagreements.is_empty(),
        "xtask/data/recovery.json and this crate describe different numbers, and every document \
         renders the JSON: {disagreements:?}"
    );
}

#[test]
fn published_bar_check_rejects_a_corrupted_bar() {
    let doc: serde_json::Value = recovery_document();
    let real: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    let corrupted: PublishedBar = PublishedBar {
        value: 90.0,
        ..real
    };
    assert_eq!(
        bar_disagreements(&corrupted, OBJECT_PCT_FLOOR).len(),
        2,
        "a bar republished at the old 90 floor must fail both its own ratio and the enforced \
         floor, otherwise this check would pass over the number the documents used to print"
    );

    let ratio_only: PublishedBar = PublishedBar {
        num: real.num / 2,
        ..real
    };
    assert_eq!(
        bar_disagreements(&ratio_only, OBJECT_PCT_FLOOR).len(),
        1,
        "halving the numerator must break the ratio leg alone"
    );

    assert!(
        bar_disagreements(&real, OBJECT_PCT_FLOOR).is_empty(),
        "the committed bar itself must stay clean"
    );
}

#[test]
fn arbitrary_recompile_equivalence_gate() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_314, GRADED) else {
        panic!(
            "no CPython {BAND_CPYTHON} interpreter found (uv python find {BAND_CPYTHON}, then \
             3.14, then known install paths). This gate is the reference behind the published \
             per-code-object figure, so its absence fails the run rather than passing it: a skip \
             here would leave floor {OBJECT_PCT_FLOOR} unenforced while the suite still reported \
             green. Install it with `uv python install {BAND_CPYTHON}`."
        );
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        (maj, min),
        (3, 14),
        "resolved interpreter at {} is {maj}.{min}, not 3.14; the pinned corpus is 3.14-specific",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULES);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "pinned module list missing at {}",
        modules.display()
    );

    let ledger_path: PathBuf = workspace_target().join("py-sibling-collision-ledger.tsv");
    let run: HarnessRun =
        run_measure_with_ledger(&python, &disrobe, &lib, &modules, Some(&ledger_path));
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!("--- harness taxonomy (stderr) ---\n{}", run.stderr);

    assert!(
        run.success,
        "harness exited {:?}\nstdout:\n{}\nstderr:\n{}",
        run.code, run.stdout, run.stderr
    );

    let m: Measurement = parse_measurement(&run.stdout).expect("parse harness measurement");
    assert_measurement_is_comparable(&m.cpython_version, &CPYTHON_314, GRADED);
    println!(
        "{}",
        population_line(PINNED_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "population {PINNED_POPULATION}: whole-module exact {} / {} ({:.2}%), sibling-count \
         collisions {}, listed modules absent from this Lib {}, measured on CPython {}",
        m.modules_exact,
        m.modules,
        m.module_pct,
        m.sibling_collisions,
        m.missing_from_lib,
        m.cpython_version
    );

    let derived_collisions: u64 = sibling_collisions_from_ledger(&ledger_path);
    assert_eq!(
        derived_collisions, m.sibling_collisions,
        "the printed sibling_collisions summary ({}) disagrees with a count independently \
         derived from the object ledger this same run wrote ({derived_collisions}): a \
         size-mismatched qualname group is a sibling collision whenever its ledger rows outnumber \
         one, or whenever its lone row is COLLISION rather than MISSING",
        m.sibling_collisions
    );

    assert!(
        m.modules >= 180,
        "only {} of the 200 pinned modules were measured ({} absent from this Lib); the corpus has \
         drifted too far to be representative - refresh the pin against the current 3.14 stdlib",
        m.modules,
        m.missing_from_lib
    );
    assert!(
        m.code_objects >= 5000,
        "only {} code objects measured; expected ~6000+ from the pinned corpus, the sample is too \
         thin to gate on",
        m.code_objects
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
         ({}/{} objects on {} modules, CPython {}). The floor is pinned at the exact figure this \
         corpus measures, so any drop is a real regression unless the stdlib sources themselves \
         moved: if this run is on a different 3.14 patch release than the one the floor was pinned \
         against, re-measure and re-pin rather than lowering the floor",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );

    assert!(
        m.modules_exact >= MODULES_EXACT_FLOOR,
        "whole-module exact recovery regressed on the pinned corpus: {} of the {} measured modules \
         came back with every code object equivalent, floor {MODULES_EXACT_FLOOR} of 200 ({} listed \
         modules absent from this Lib). This numerator is the whole-module figure the documents \
         quote, so it is floored here rather than printed and forgotten",
        m.modules_exact,
        m.modules,
        m.missing_from_lib
    );

    let exact_pct: f64 = f64::from(u32::try_from(m.modules_exact).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(PINNED_MODULE_COUNT).unwrap_or(u32::MAX))
        * 100.0;
    assert!(
        exact_pct >= MODULES_EXACT_PCT_FLOOR,
        "the documents publish {MODULES_EXACT_PCT_FLOOR}% as the whole-module rate over the \
         {PINNED_MODULE_COUNT}-module pinned corpus, and this run measured {exact_pct:.1}% from \
         {} modules. The percentage is cut from the same numerator as the count, so it is floored \
         here rather than left as a hand-typed derivative nothing checks",
        m.modules_exact
    );

    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    assert_eq!(
        (bar.num, bar.den),
        (m.objects_ok, m.code_objects),
        "xtask/data/recovery.json publishes {}/{} for the pinned corpus and every document \
         renders that pair, but this run measured {}/{} on CPython {}",
        bar.num,
        bar.den,
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
}

fn probe_sibling_group_charges(python: &Path, harness_dir: &Path) -> Vec<(u64, u64, bool, u64)> {
    let script: &str = r#"
import json
import sys

sys.path.insert(0, sys.argv[1])
from py_arbitrary_measure import sibling_group_charges


def objs(n):
    return [compile("x = 1", "<constructed>", "exec") for _ in range(n)]


cases = [(1, 0), (1, 1), (1, 2), (1, 5), (2, 0), (2, 1), (2, 3), (5, 1), (0, 0)]
out = []
for a, b in cases:
    collision, charges = sibling_group_charges(objs(a), objs(b))
    out.append([a, b, collision, len(charges)])
print(json.dumps(out))
"#;
    let output: std::process::Output = Command::new(python)
        .arg("-c")
        .arg(script)
        .arg(harness_dir)
        .stdin(Stdio::null())
        .output()
        .expect("spawn sibling_group_charges probe");
    assert!(
        output.status.success(),
        "sibling_group_charges probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let rows: Vec<serde_json::Value> = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e: serde_json::Error| panic!("parse probe output: {e}: {stdout}"));
    rows.into_iter()
        .map(|row: serde_json::Value| {
            let arr: Vec<serde_json::Value> = row.as_array().cloned().unwrap_or_default();
            let a: u64 = arr.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
            let b: u64 = arr.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0);
            let collision: bool = arr
                .get(2)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let charges: u64 = arr.get(3).and_then(serde_json::Value::as_u64).unwrap_or(0);
            (a, b, collision, charges)
        })
        .collect()
}

#[test]
fn sibling_group_charges_counts_a_recovered_side_collision() {
    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_314, GRADED) else {
        panic!(
            "no CPython {BAND_CPYTHON} interpreter found; the sibling-group counter is defined \
             against {BAND_CPYTHON} code objects. Install it with `uv python install \
             {BAND_CPYTHON}`."
        );
    };
    let harness_dir: PathBuf = manifest_dir().join("tests/harness");
    let rows: Vec<(u64, u64, bool, u64)> = probe_sibling_group_charges(&python, &harness_dir);
    let case = |a: u64, b: u64| -> (bool, u64) {
        rows.iter()
            .find(|&&(ra, rb, _, _)| ra == a && rb == b)
            .map_or_else(
                || panic!("probe did not report the ({a}, {b}) case"),
                |&(_, _, collision, charges)| (collision, charges),
            )
    };

    assert!(
        case(1, 2).0,
        "one original against two recovered is the exact shape BUG-055 reported uncounted; the \
         summary counter must flag it even though the original side never held a sibling"
    );
    assert!(
        case(1, 5).0,
        "one original against five recovered must also count"
    );
    assert!(
        case(2, 3).0,
        "an original sibling group outgrown by an even larger recovered group must count"
    );
    assert!(
        case(2, 0).0,
        "an original sibling group larger than the recovered side must still count"
    );
    assert!(
        case(2, 1).0,
        "a partially-recovered original sibling group must still count"
    );
    assert!(
        case(5, 1).0,
        "a large original sibling group missing most of its recovered siblings must still count"
    );
    assert!(
        !case(1, 0).0,
        "a single object that failed to recover at all has no sibling to collide with"
    );
    assert!(!case(0, 0).0, "an empty group carries no sibling ambiguity");

    for (a, b) in [
        (1u64, 0u64),
        (1, 1),
        (1, 2),
        (1, 5),
        (2, 0),
        (2, 1),
        (2, 3),
        (5, 1),
        (0, 0),
    ] {
        assert_eq!(
            case(a, b).1,
            a,
            "charges must cover every original object in the ({a}, {b}) group exactly once, so \
             MISSING and COLLISION always sum to the group size"
        );
    }
}

fn sibling_collisions_from_ledger(ledger_path: &Path) -> u64 {
    let ledger_raw: String = std::fs::read_to_string(ledger_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", ledger_path.display()));
    let mut groups: BTreeMap<(String, String), Vec<&str>> = BTreeMap::new();
    for line in ledger_raw.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let Ok([module, qualname, _position, verdict]): Result<[&str; 4], Vec<&str>> =
            fields.try_into()
        else {
            panic!("malformed ledger row: {line}");
        };
        if verdict == "MISSING" || verdict == "COLLISION" {
            groups
                .entry((module.to_owned(), qualname.to_owned()))
                .or_default()
                .push(verdict);
        }
    }
    u64::try_from(
        groups
            .values()
            .filter(|verdicts: &&Vec<&str>| {
                verdicts.len() > 1 || verdicts.first().copied() == Some("COLLISION")
            })
            .count(),
    )
    .unwrap_or(u64::MAX)
}
