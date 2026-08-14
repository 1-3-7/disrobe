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
use std::time::{Duration, Instant};

use common::band_gate::{
    BandPopulation, BandPublication, CPYTHON_39, OPCODES_INTRODUCED_IN_3_9,
    OPCODES_RETIRED_AFTER_3_8, PINNED_MODULE_COUNT, PINNED_MODULE_LIST,
    assert_band_reaches_its_own_bytecode, assert_population_pin_rejects_shrinkage,
    assert_publication_matches_the_gate, population_disagreements, resolve_band_interpreter,
};
use common::stdlib_measure::{
    BandReach, HarnessRun, MEASURE_HARNESS, Measurement, PublishedBar, REACH_HARNESS,
    bar_disagreements, find_disrobe, interpreter_release, interpreter_stdlib, interpreter_version,
    manifest_dir, parse_measurement, parse_reach, population_line, recovery_document,
    run_measure_bounded, run_reach, workspace_target,
};

const BAND_LABEL: &str = "CPython 3.9 (157 of the pinned modules)";
const BAND_LABEL_PREFIX: &str = "CPython 3.9 (";
const BAND_POPULATION: &str = "cpython-39-band";

const OBJECT_PCT_FLOOR: f64 = 93.27;
const BAND_OBJECTS_OK: u64 = 4_881;
const BAND_CODE_OBJECTS: u64 = 5_233;
const BAND_MODULES: u64 = 157;
const BAND_MODULES_EXACT_FLOOR: u64 = 84;
const BAND_MISSING_FROM_LIB: u64 = 43;
const BAND_POSONLY_OBJECTS: u64 = 22;
const BAND_CPYTHON: &str = "3.9.25";
const BAND_PLATFORM: &str = "windows x86_64";
const BAND_MEASURE_CEILING: Duration = Duration::from_mins(40);

const fn enforced() -> BandPopulation {
    BandPopulation {
        objects_ok: BAND_OBJECTS_OK,
        code_objects: BAND_CODE_OBJECTS,
        modules: BAND_MODULES,
    }
}

const fn enforced_bar() -> PublishedBar {
    PublishedBar {
        value: OBJECT_PCT_FLOOR,
        num: BAND_OBJECTS_OK,
        den: BAND_CODE_OBJECTS,
        modules: BAND_MODULES,
    }
}

fn graded() -> String {
    format!(
        "the {BAND_POPULATION} figure of {BAND_OBJECTS_OK} / {BAND_CODE_OBJECTS} code objects over \
         {BAND_MODULES} modules, measured on CPython {BAND_CPYTHON} ({BAND_PLATFORM})"
    )
}

#[test]
fn published_39_band_bar_agrees_with_the_counts_this_gate_enforces() {
    let doc: serde_json::Value = recovery_document();

    println!("=== CPYTHON 3.9 BAND ===");
    println!(
        "{}",
        population_line(
            BAND_POPULATION,
            BAND_OBJECTS_OK,
            BAND_CODE_OBJECTS,
            BAND_MODULES
        )
    );
    println!(
        "this case decompiles nothing. It proves the counts \
         `arbitrary_recompile_equivalence_gate_39` enforces describe one population, and that they \
         match whatever xtask/data/recovery.json publishes for this band. The measurement against \
         CPython {BAND_CPYTHON} is the gate below."
    );

    let self_disagreements: Vec<String> = bar_disagreements(&enforced_bar(), OBJECT_PCT_FLOOR);
    assert!(
        self_disagreements.is_empty(),
        "the {BAND_POPULATION} constants disagree with each other before any published bar is \
         consulted: {self_disagreements:?}"
    );

    assert_eq!(
        BAND_MODULES + BAND_MISSING_FROM_LIB,
        PINNED_MODULE_COUNT,
        "this gate expects {BAND_MODULES} measured modules and {BAND_MISSING_FROM_LIB} absent from \
         the 3.9 Lib, which does not account for all {PINNED_MODULE_COUNT} pinned module paths"
    );
    const {
        assert!(
            BAND_MODULES_EXACT_FLOOR < BAND_MODULES,
            "BAND_MODULES_EXACT_FLOOR has to stay under BAND_MODULES, or the whole-module floor \
             can never bind"
        );
        assert!(
            BAND_OBJECTS_OK < BAND_CODE_OBJECTS,
            "BAND_OBJECTS_OK has to stay under BAND_CODE_OBJECTS, or the band claims nothing is \
             left unrecovered and the shrinkage control has no unrecovered objects to drop"
        );
    }

    let publication: BandPublication = assert_publication_matches_the_gate(
        &doc,
        BAND_LABEL_PREFIX,
        BAND_LABEL,
        &enforced(),
        OBJECT_PCT_FLOOR,
        BAND_CPYTHON,
    );
    match publication {
        BandPublication::Published { label, bar } => println!(
            "bound to the published bar `{label}`: {} / {} over {} modules",
            bar.num, bar.den, bar.modules
        ),
        BandPublication::Unpublished => println!(
            "xtask/data/recovery.json carries no bar starting `{BAND_LABEL_PREFIX}`, so this band \
             is measured here and published nowhere. The counts above are the whole claim."
        ),
    }
}

#[test]
fn a_shrunken_39_band_population_is_rejected() {
    assert_population_pin_rejects_shrinkage(&enforced_bar(), OBJECT_PCT_FLOOR, BAND_POPULATION);
}

#[test]
fn the_39_band_population_carries_the_bytecode_3_9_introduced() {
    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_39, &graded()) else {
        return;
    };

    let Some(release): Option<String> = interpreter_release(&python) else {
        panic!(
            "could not read the release of the interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        release,
        BAND_CPYTHON,
        "the resolved interpreter at {} is CPython {release}, not the {BAND_CPYTHON} this band \
         names, so its Lib is a different population",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };
    let harness: PathBuf = manifest_dir().join(REACH_HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
    assert!(
        harness.is_file(),
        "bytecode-reach harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "pinned module list missing at {}",
        modules.display()
    );

    let run: HarnessRun = run_reach(&python, &lib, &modules);
    assert!(
        run.success,
        "the bytecode-reach harness exited {:?}\nstdout:\n{}\nstderr:\n{}",
        run.code, run.stdout, run.stderr
    );
    let reach: BandReach = parse_reach(&run.stdout).unwrap_or_else(|e: String| panic!("{e}"));

    println!("=== CPYTHON 3.9 BYTECODE REACH ===");
    println!(
        "CPython {} compiled {} of the {} pinned modules into {} code objects, {} of them \
         declaring positional-only parameters, carrying {} distinct opcodes. CPython's own \
         compiler and dis module produce these counts; disrobe is not in this path.",
        reach.cpython_version,
        reach.modules,
        reach.pinned,
        reach.code_objects,
        reach.posonly_objects,
        reach.opnames.len()
    );

    assert_eq!(
        reach.pinned, PINNED_MODULE_COUNT,
        "the reach harness read {} module paths from the pinned corpus, not {PINNED_MODULE_COUNT}",
        reach.pinned
    );
    assert_eq!(
        reach.missing_from_lib, BAND_MISSING_FROM_LIB,
        "{} of the pinned modules are absent from this 3.9 Lib, not the {BAND_MISSING_FROM_LIB} \
         this band records",
        reach.missing_from_lib
    );
    assert_eq!(
        reach.modules, BAND_MODULES,
        "the reach harness walked {} modules, not the {BAND_MODULES} the recompile gate measures, \
         so the two are not describing one population",
        reach.modules
    );
    assert_eq!(
        reach.code_objects, BAND_CODE_OBJECTS,
        "CPython {BAND_CPYTHON} compiles the pinned modules into {} code objects, not the \
         {BAND_CODE_OBJECTS} this band names as its denominator. This count comes from CPython \
         with no disrobe in the path, so a disagreement means the published denominator is wrong \
         and both halves of the fraction need re-measuring, never that this walk should be \
         relaxed",
        reach.code_objects
    );
    assert_eq!(
        reach.posonly_objects, BAND_POSONLY_OBJECTS,
        "{} of the measured code objects declare positional-only parameters, not the \
         {BAND_POSONLY_OBJECTS} this band records, and the equivalence check compares \
         co_posonlyargcount. A CPython 3.9 patch release whose Lib uses the syntax differently \
         needs a re-measured band, not an edited count",
        reach.posonly_objects
    );

    assert_band_reaches_its_own_bytecode(
        &reach,
        OPCODES_INTRODUCED_IN_3_9,
        OPCODES_RETIRED_AFTER_3_8,
        BAND_POPULATION,
    );
}

#[test]
fn arbitrary_recompile_equivalence_gate_39() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_39, &graded()) else {
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
        (3, 9),
        "resolved interpreter at {} is {maj}.{min}, not 3.9",
        python.display()
    );

    let Some(release): Option<String> = interpreter_release(&python) else {
        panic!(
            "could not read the release of the interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        release,
        BAND_CPYTHON,
        "the resolved interpreter at {} is CPython {release} and this band is pinned to \
         {BAND_CPYTHON}. A different patch release ships a different Lib, so the figure would name \
         a version it was never measured on. This case stops here rather than measuring: \
         re-measure the band on {BAND_CPYTHON}, or re-pin every count in this file against the \
         release you have",
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

    let started: Instant = Instant::now();
    let run: HarnessRun = run_measure_bounded(
        &python,
        &disrobe,
        &lib,
        &modules,
        BAND_MEASURE_CEILING,
        BAND_POPULATION,
    );
    let elapsed: Duration = started.elapsed();
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS (3.9) ===");
    println!("interpreter : {} ({release})", python.display());
    println!("platform    : {BAND_PLATFORM}");
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!(
        "wall clock  : {:.1}s of the {}s ceiling this band allows one measurement",
        elapsed.as_secs_f64(),
        BAND_MEASURE_CEILING.as_secs()
    );
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
        m.cpython_version, BAND_CPYTHON,
        "the harness ran under CPython {} and this band names {BAND_CPYTHON}",
        m.cpython_version
    );
    assert_eq!(
        m.listed_modules, PINNED_MODULE_COUNT,
        "the harness read {} module paths from the pinned corpus, not {PINNED_MODULE_COUNT}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, BAND_MISSING_FROM_LIB,
        "{} of the {PINNED_MODULE_COUNT} pinned modules are absent from this 3.9 Lib, not the \
         {BAND_MISSING_FROM_LIB} this band records; the band was pinned against CPython \
         {BAND_CPYTHON} and a release that ships a different Lib needs a fresh measurement plus a \
         re-published numerator, denominator and module count, never a lowered floor (this run: \
         CPython {})",
        m.missing_from_lib, m.cpython_version
    );
    assert_eq!(
        m.modules, BAND_MODULES,
        "only {} of the pinned modules were measured on 3.9, not {BAND_MODULES}; a run that \
         inspects fewer modules must score worse, not measure itself against a smaller population \
         (CPython {})",
        m.modules, m.cpython_version
    );
    assert_eq!(
        m.code_objects, BAND_CODE_OBJECTS,
        "the {BAND_POPULATION} denominator is pinned by equality: this run walked {} code objects, \
         the band names {BAND_CODE_OBJECTS} (CPython {BAND_CPYTHON}, measured {}). A different \
         denominator is a different population, so re-measure and re-publish both halves of the \
         fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed on 3.9: {:.2}% < floor \
         {OBJECT_PCT_FLOOR}% ({} / {} objects on {} modules, CPython {}). The floor is the exact \
         figure this band records, so it has no slack to absorb a regression and only ever rises",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= BAND_MODULES_EXACT_FLOOR,
        "whole-module exact recovery regressed on 3.9: {} of the {} measured modules came back \
         with every code object equivalent, floor {BAND_MODULES_EXACT_FLOOR}",
        m.modules_exact,
        m.modules
    );

    let measured: BandPopulation = BandPopulation {
        objects_ok: m.objects_ok,
        code_objects: m.code_objects,
        modules: m.modules,
    };
    let disagreements: Vec<String> = population_disagreements(&measured, &enforced_bar());
    assert!(
        disagreements.is_empty(),
        "this gate enforces {BAND_OBJECTS_OK} / {BAND_CODE_OBJECTS} over {BAND_MODULES} modules \
         for the 3.9 band, but this run measured {} / {} over {} modules on CPython {}: \
         {disagreements:?}",
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
}
