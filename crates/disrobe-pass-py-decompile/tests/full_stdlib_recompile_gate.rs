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

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::stdlib_measure::{
    FULL_POPULATION, HarnessRun, MEASURE_HARNESS, Measurement, PINNED_POPULATION, PublishedBar,
    bar_disagreements, find_disrobe, find_python_314, interpreter_stdlib, interpreter_version,
    manifest_dir, parse_measurement, population_line, published_bar, published_detail,
    read_module_list, recovery_document, run_measure, workspace_target,
};

const FULL_MODULE_LIST: &str = "tests/harness/full_modules_314.txt";
const PINNED_MODULE_LIST: &str = "tests/harness/pinned_modules_314.txt";

const FULL_BAR_LABEL: &str = "full 574-module stdlib (representative)";
const PINNED_BAR_LABEL: &str = "200-module pinned corpus";

const FULL_MODULES: u64 = 574;
const FULL_CODE_OBJECTS: u64 = 18_276;
const FULL_OBJECTS_OK_FLOOR: u64 = 17_378;
const FULL_MODULES_EXACT_FLOOR: u64 = 331;
const FULL_OBJECT_PCT_FLOOR: f64 = 95.09;

const PINNED_MODULES: u64 = 200;
const PINNED_CODE_OBJECTS: u64 = 6_286;
const PINNED_OBJECTS_OK: u64 = 6_072;

const PINNED_CPYTHON: &str = "3.14.5";

fn module_lists() -> (Vec<String>, Vec<String>) {
    let full_path: PathBuf = manifest_dir().join(FULL_MODULE_LIST);
    let pinned_path: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
    assert!(
        full_path.is_file(),
        "the {FULL_POPULATION} module list is missing at {}; without it the published full-stdlib \
         figure has no committed population",
        full_path.display()
    );
    assert!(
        pinned_path.is_file(),
        "the {PINNED_POPULATION} module list is missing at {}",
        pinned_path.display()
    );
    let full: Vec<String> = read_module_list(&full_path).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: Vec<String> =
        read_module_list(&pinned_path).unwrap_or_else(|e: String| panic!("{e}"));
    (full, pinned)
}

#[test]
fn the_full_stdlib_population_contains_every_pinned_module() {
    let (full, pinned): (Vec<String>, Vec<String>) = module_lists();
    let full_count: u64 = u64::try_from(full.len()).expect("module count fits u64");
    let pinned_count: u64 = u64::try_from(pinned.len()).expect("module count fits u64");

    assert_eq!(
        full_count, FULL_MODULES,
        "the {FULL_POPULATION} list carries {full_count} module paths, not the {FULL_MODULES} the \
         published figure names; a shorter list measures a smaller population under the same \
         headline, so re-measure and re-publish both the numerator and the denominator rather than \
         trimming the list"
    );
    assert_eq!(
        pinned_count, PINNED_MODULES,
        "the {PINNED_POPULATION} list carries {pinned_count} module paths, not {PINNED_MODULES}"
    );

    let full_set: BTreeSet<&str> = full.iter().map(String::as_str).collect();
    assert_eq!(
        full_set.len(),
        full.len(),
        "the {FULL_POPULATION} list repeats a module path, which would count one module's code \
         objects twice in the published denominator"
    );

    let absent: Vec<&str> = pinned
        .iter()
        .map(String::as_str)
        .filter(|module: &&str| !full_set.contains(module))
        .collect();
    assert!(
        absent.is_empty(),
        "{} of the {PINNED_POPULATION} modules are not members of the {FULL_POPULATION} list, so \
         the two published figures do not describe nested populations and neither one bounds the \
         other: {absent:?}",
        absent.len()
    );
    assert!(
        full_count > pinned_count,
        "the {FULL_POPULATION} list ({full_count} modules) must be strictly larger than the \
         {PINNED_POPULATION} list ({pinned_count} modules); equal sizes mean one figure was \
         published over the other's population"
    );
}

#[test]
fn published_full_stdlib_bar_agrees_with_the_gated_population() {
    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    println!("=== PUBLISHED PYTHON RECOVERY POPULATIONS ===");
    println!(
        "{}",
        population_line(FULL_POPULATION, full.num, full.den, full.modules)
    );
    println!(
        "{}",
        population_line(PINNED_POPULATION, pinned.num, pinned.den, pinned.modules)
    );

    let disagreements: Vec<String> = bar_disagreements(&full, FULL_OBJECT_PCT_FLOOR);
    assert!(
        disagreements.is_empty(),
        "the published `{FULL_BAR_LABEL}` bar and the floor this gate enforces describe different \
         numbers, and every document renders the JSON: {disagreements:?}"
    );

    assert_eq!(
        (full.num, full.den, full.modules),
        (FULL_OBJECTS_OK_FLOOR, FULL_CODE_OBJECTS, FULL_MODULES),
        "the published `{FULL_BAR_LABEL}` bar reads {}/{} over {} modules, but this gate enforces \
         {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} over {FULL_MODULES}",
        full.num,
        full.den,
        full.modules
    );
    assert_eq!(
        (pinned.num, pinned.den, pinned.modules),
        (PINNED_OBJECTS_OK, PINNED_CODE_OBJECTS, PINNED_MODULES),
        "the published `{PINNED_BAR_LABEL}` bar reads {}/{} over {} modules, but the pinned corpus \
         gate measures {PINNED_OBJECTS_OK}/{PINNED_CODE_OBJECTS} over {PINNED_MODULES}",
        pinned.num,
        pinned.den,
        pinned.modules
    );
    assert!(
        full.den > pinned.den && full.modules > pinned.modules,
        "the two Python figures must stay separate populations: {FULL_POPULATION} publishes \
         {}/{} over {} modules and {PINNED_POPULATION} publishes {}/{} over {} modules, and the \
         full population must be the strictly larger one",
        full.num,
        full.den,
        full.modules,
        pinned.num,
        pinned.den,
        pinned.modules
    );

    let full_detail: String =
        published_detail(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned_detail: String =
        published_detail(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let full_den: String = FULL_CODE_OBJECTS.to_string();
    let pinned_den: String = PINNED_CODE_OBJECTS.to_string();
    assert!(
        full_detail.contains(&full_den) && !full_detail.contains(&pinned_den),
        "the `{FULL_BAR_LABEL}` detail must state its own denominator {full_den} and never the \
         {PINNED_POPULATION} denominator {pinned_den}, otherwise the two figures read as one \
         population: {full_detail}"
    );
    assert!(
        pinned_detail.contains(&pinned_den) && !pinned_detail.contains(&full_den),
        "the `{PINNED_BAR_LABEL}` detail must state its own denominator {pinned_den} and never the \
         {FULL_POPULATION} denominator {full_den}: {pinned_detail}"
    );
}

#[test]
fn a_bar_that_blends_the_two_populations_is_rejected() {
    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let pinned: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    let full_over_pinned_denominator: PublishedBar = PublishedBar {
        den: pinned.den,
        ..full
    };
    assert_eq!(
        bar_disagreements(&full_over_pinned_denominator, FULL_OBJECT_PCT_FLOOR).len(),
        1,
        "publishing the {FULL_POPULATION} numerator over the {PINNED_POPULATION} denominator must \
         break the ratio leg, otherwise the denominator is not really pinned"
    );

    let pinned_percentage_on_full_population: PublishedBar = PublishedBar {
        value: pinned.value,
        ..full
    };
    assert_eq!(
        bar_disagreements(&pinned_percentage_on_full_population, FULL_OBJECT_PCT_FLOOR).len(),
        2,
        "reprinting the {PINNED_POPULATION} percentage against the {FULL_POPULATION} counts must \
         break both the ratio leg and the enforced-floor leg; that blend is the exact defect this \
         gate exists to catch"
    );

    let short_numerator: PublishedBar = PublishedBar {
        num: full.num - 1,
        ..full
    };
    assert_eq!(
        bar_disagreements(&short_numerator, FULL_OBJECT_PCT_FLOOR).len(),
        0,
        "a one-object numerator drift stays inside the 0.05 percentage-point ratio tolerance, so \
         the numerator floor in the measurement gate is what catches it, not this ratio check"
    );

    assert!(
        bar_disagreements(&full, FULL_OBJECT_PCT_FLOOR).is_empty(),
        "the committed {FULL_POPULATION} bar itself must stay clean"
    );
    assert!(
        bar_disagreements(&pinned, pinned.value).is_empty(),
        "the committed {PINNED_POPULATION} bar itself must stay clean against its own value"
    );
}

#[test]
#[ignore = "measures the whole 574-module CPython 3.14 stdlib through the real CLI; minutes, not \
            seconds, so CI drives it from the schedule trigger with `cargo test -p \
            disrobe-pass-py-decompile --test full_stdlib_recompile_gate -- --ignored --nocapture`"]
fn full_stdlib_recompile_equivalence_gate() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the {FULL_POPULATION} gate \
             measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14 interpreter found (uv python find 3.14 / known install paths). This \
             gate is the reference behind the published {FULL_POPULATION} figure of \
             {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} code objects, so its absence fails the \
             run rather than passing it. Install one with `uv python install 3.14`."
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
        "resolved interpreter at {} is {maj}.{min}, not 3.14; the {FULL_POPULATION} list is \
         3.14-specific",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let modules: PathBuf = manifest_dir().join(FULL_MODULE_LIST);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "the {FULL_POPULATION} module list is missing at {}",
        modules.display()
    );

    let run: HarnessRun = run_measure(&python, &disrobe, &lib, &modules);
    println!("=== FULL STDLIB RECOMPILE-EQUIVALENCE GATE ===");
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
        population_line(FULL_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "{}",
        population_line(
            PINNED_POPULATION,
            PINNED_OBJECTS_OK,
            PINNED_CODE_OBJECTS,
            PINNED_MODULES
        )
    );
    println!(
        "population {FULL_POPULATION}: whole-module exact {} / {} ({:.2}%), sibling-count \
         collisions {}, measured on CPython {}",
        m.modules_exact, m.modules, m.module_pct, m.sibling_collisions, m.cpython_version
    );

    assert_eq!(
        m.listed_modules, FULL_MODULES,
        "the harness read {} module paths from the {FULL_POPULATION} list, not {FULL_MODULES}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, 0,
        "{} of the {FULL_MODULES} listed modules are absent from this interpreter's Lib, so this \
         run cannot measure the published population; the denominator was pinned against CPython \
         {PINNED_CPYTHON}, and a patch release that adds or drops stdlib modules needs a fresh \
         measurement plus a re-published numerator and denominator, never a lowered floor",
        m.missing_from_lib
    );
    assert_eq!(
        m.modules, FULL_MODULES,
        "only {} of the {FULL_MODULES} listed modules were measured; a run that inspects fewer \
         modules must score worse, not measure itself against a smaller population",
        m.modules
    );
    assert_eq!(
        m.code_objects, FULL_CODE_OBJECTS,
        "the {FULL_POPULATION} denominator is pinned by equality: this run walked {} code objects, \
         the published figure names {FULL_CODE_OBJECTS} (CPython {PINNED_CPYTHON}, measured \
         {}). A different denominator is a different population, so re-measure and re-publish \
         both halves of the fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.objects_ok >= FULL_OBJECTS_OK_FLOOR,
        "{FULL_POPULATION} per-code-object recompile-equivalence regressed: {} / {} recovered, \
         floor {FULL_OBJECTS_OK_FLOOR} / {FULL_CODE_OBJECTS} ({FULL_OBJECT_PCT_FLOOR}%) on \
         CPython {}. The floor is the exact figure this population measures, so any drop is a \
         real regression and the floor only ever rises",
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
    assert!(
        m.object_pct >= FULL_OBJECT_PCT_FLOOR,
        "{FULL_POPULATION} measured {:.2}%, below the published {FULL_OBJECT_PCT_FLOOR}% \
         ({} / {} on {} modules, CPython {})",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= FULL_MODULES_EXACT_FLOOR,
        "{FULL_POPULATION} whole-module exact recovery regressed: {} / {} modules came back with \
         every code object equivalent, floor {FULL_MODULES_EXACT_FLOOR} / {FULL_MODULES}",
        m.modules_exact,
        m.modules
    );
    assert!(
        m.code_objects != PINNED_CODE_OBJECTS && m.modules != PINNED_MODULES,
        "this run measured {} code objects over {} modules, which is the {PINNED_POPULATION} \
         population, not {FULL_POPULATION}; the two must never be measured as one",
        m.code_objects,
        m.modules
    );

    let doc: serde_json::Value = recovery_document();
    let full: PublishedBar =
        published_bar(&doc, FULL_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    assert_eq!(
        (full.num, full.den),
        (FULL_OBJECTS_OK_FLOOR, FULL_CODE_OBJECTS),
        "xtask/data/recovery.json publishes {}/{} for {FULL_POPULATION} and every document renders \
         that pair, but this gate enforces {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS}",
        full.num,
        full.den
    );
    assert!(
        m.objects_ok >= full.num,
        "this run recovered {} of {} code objects, under the published {}/{}",
        m.objects_ok,
        m.code_objects,
        full.num,
        full.den
    );
    if m.objects_ok > full.num {
        println!(
            "population {FULL_POPULATION} now measures {} / {} code objects, above the published \
             {} / {}; raise the published numerator and this gate's floor to the new figure",
            m.objects_ok, m.code_objects, full.num, full.den
        );
    }
}
