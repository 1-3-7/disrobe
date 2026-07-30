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

use std::path::PathBuf;

use common::stdlib_measure::{
    HarnessRun, MEASURE_HARNESS, Measurement, PINNED_POPULATION, PublishedBar, bar_disagreements,
    find_disrobe, find_python_314, interpreter_stdlib, interpreter_version, manifest_dir,
    parse_measurement, population_line, published_bar, recovery_document, run_measure,
    workspace_target,
};

const PINNED_MODULES: &str = "tests/harness/pinned_modules_314.txt";

const OBJECT_PCT_FLOOR: f64 = 96.60;
const MODULES_EXACT_FLOOR: u64 = 122;

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

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14 interpreter found (uv python find 3.14 / known install paths). This \
             gate is the reference behind the published per-code-object figure, so its absence \
             fails the run rather than passing it: a skip here would leave floor \
             {OBJECT_PCT_FLOOR} unenforced while the suite still reported green. Install one with \
             `uv python install 3.14`."
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

    let run: HarnessRun = run_measure(&python, &disrobe, &lib, &modules);
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
