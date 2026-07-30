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

use common::band_gate::{
    BandPopulation, CPYTHON_315, PINNED_MODULE_COUNT, PINNED_MODULE_LIST,
    assert_bands_are_distinct_populations, assert_detail_states_its_own_counts,
    assert_population_pin_rejects_shrinkage, population_disagreements, published_band_bar,
    resolve_band_interpreter,
};
use common::stdlib_measure::{
    HarnessRun, MEASURE_HARNESS, Measurement, PublishedBar, bar_disagreements, find_disrobe,
    interpreter_stdlib, interpreter_version, manifest_dir, parse_measurement, population_line,
    published_detail, recovery_document, run_measure, workspace_target,
};

const BAND_LABEL: &str = "CPython 3.15 (199 of the pinned modules)";
const BAND_POPULATION: &str = "cpython-315-band";

const OBJECT_PCT_FLOOR: f64 = 96.03;
const BAND_OBJECTS_OK: u64 = 6_214;
const BAND_CODE_OBJECTS: u64 = 6_471;
const BAND_MODULES: u64 = 199;
const BAND_MODULES_EXACT_FLOOR: u64 = 119;
const BAND_MISSING_FROM_LIB: u64 = 1;
const BAND_CPYTHON: &str = "3.15.0b1";

fn published() -> PublishedBar {
    let doc: serde_json::Value = recovery_document();
    published_band_bar(&doc, BAND_LABEL)
}

fn graded() -> String {
    format!(
        "the published {BAND_POPULATION} figure of {BAND_OBJECTS_OK} / {BAND_CODE_OBJECTS} code \
         objects over {BAND_MODULES} modules"
    )
}

#[test]
fn published_315_band_bar_agrees_with_the_counts_this_gate_enforces() {
    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar = published_band_bar(&doc, BAND_LABEL);

    println!("=== PUBLISHED CPYTHON 3.15 BAND ===");
    println!(
        "{}",
        population_line(BAND_POPULATION, bar.num, bar.den, bar.modules)
    );
    println!(
        "this case reads xtask/data/recovery.json and compares it against the counts \
         `arbitrary_recompile_equivalence_gate_315` enforces. It decompiles nothing, so it proves \
         the chart and this crate name one population, not that the population is the one CPython \
         {BAND_CPYTHON} measures. That measurement is the gate below."
    );

    let disagreements: Vec<String> = bar_disagreements(&bar, OBJECT_PCT_FLOOR);
    assert!(
        disagreements.is_empty(),
        "the published `{BAND_LABEL}` bar and the floor this gate enforces describe different \
         numbers, and the recovery chart renders the JSON: {disagreements:?}"
    );

    let enforced: BandPopulation = BandPopulation {
        objects_ok: BAND_OBJECTS_OK,
        code_objects: BAND_CODE_OBJECTS,
        modules: BAND_MODULES,
    };
    let against_published: Vec<String> = population_disagreements(&enforced, &bar);
    assert!(
        against_published.is_empty(),
        "the published `{BAND_LABEL}` bar reads {} / {} over {} modules, but this gate enforces \
         {BAND_OBJECTS_OK} / {BAND_CODE_OBJECTS} over {BAND_MODULES}: {against_published:?}",
        bar.num,
        bar.den,
        bar.modules
    );

    assert_eq!(
        BAND_MODULES + BAND_MISSING_FROM_LIB,
        PINNED_MODULE_COUNT,
        "this gate expects {BAND_MODULES} measured modules and {BAND_MISSING_FROM_LIB} absent from \
         the 3.15 Lib, which does not account for all {PINNED_MODULE_COUNT} pinned module paths"
    );

    let detail: String =
        published_detail(&doc, BAND_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    assert_detail_states_its_own_counts(&detail, &bar, BAND_LABEL);
    assert!(
        detail.contains(BAND_CPYTHON),
        "the `{BAND_LABEL}` detail never names the interpreter release the counts were measured \
         on, so a re-measurement on another 3.15 prerelease cannot be told apart from this one: \
         {detail}"
    );

    assert_bands_are_distinct_populations(&doc, BAND_LABEL);
}

#[test]
fn a_shrunken_315_band_population_is_rejected() {
    assert_population_pin_rejects_shrinkage(&published(), OBJECT_PCT_FLOOR, BAND_POPULATION);
}

#[test]
fn arbitrary_recompile_equivalence_gate_315() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_315, &graded()) else {
        return;
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        (maj, min),
        (3, 15),
        "resolved interpreter at {} is {maj}.{min}, not 3.15",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
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
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS (3.15) ===");
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
        population_line(BAND_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "population {BAND_POPULATION}: whole-module exact {} / {} ({:.2}%), sibling-count \
         collisions {}, pinned modules absent from this Lib {}, measured on CPython {}",
        m.modules_exact,
        m.modules,
        m.module_pct,
        m.sibling_collisions,
        m.missing_from_lib,
        m.cpython_version
    );

    assert_eq!(
        m.listed_modules, PINNED_MODULE_COUNT,
        "the harness read {} module paths from the pinned corpus, not {PINNED_MODULE_COUNT}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, BAND_MISSING_FROM_LIB,
        "{} of the {PINNED_MODULE_COUNT} pinned modules are absent from this 3.15 Lib, not the \
         {BAND_MISSING_FROM_LIB} the published detail states; the band was pinned against CPython \
         {BAND_CPYTHON} and a release that ships a different Lib needs a fresh measurement plus a \
         re-published numerator, denominator and module count, never a lowered floor (this run: \
         CPython {})",
        m.missing_from_lib, m.cpython_version
    );
    assert_eq!(
        m.modules, BAND_MODULES,
        "only {} of the pinned modules were measured on 3.15, not {BAND_MODULES}; a run that \
         inspects fewer modules must score worse, not measure itself against a smaller population \
         (CPython {})",
        m.modules, m.cpython_version
    );
    assert_eq!(
        m.code_objects, BAND_CODE_OBJECTS,
        "the {BAND_POPULATION} denominator is pinned by equality: this run walked {} code objects, \
         the published band names {BAND_CODE_OBJECTS} (CPython {BAND_CPYTHON}, measured {}). A \
         different denominator is a different population, so re-measure and re-publish both halves \
         of the fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed on 3.15: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
         ({} / {} objects on {} modules, CPython {}). The floor is the exact figure this band \
         publishes, so it has no slack to absorb a regression and only ever rises",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= BAND_MODULES_EXACT_FLOOR,
        "whole-module exact recovery regressed on 3.15: {} of the {} measured modules came back \
         with every code object equivalent, floor {BAND_MODULES_EXACT_FLOOR}",
        m.modules_exact,
        m.modules
    );

    let bar: PublishedBar = published();
    let measured: BandPopulation = BandPopulation {
        objects_ok: m.objects_ok,
        code_objects: m.code_objects,
        modules: m.modules,
    };
    let disagreements: Vec<String> = population_disagreements(&measured, &bar);
    assert!(
        disagreements.is_empty(),
        "xtask/data/recovery.json publishes {} / {} over {} modules for the 3.15 band and the \
         recovery chart renders that triple, but this run measured {} / {} over {} modules on \
         CPython {}: {disagreements:?}",
        bar.num,
        bar.den,
        bar.modules,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
}
