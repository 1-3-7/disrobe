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
use std::fs;
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

const SAMPLE_POPULATION: &str = "stdlib-sample-115";
const SAMPLE_SCRATCH_DIR: &str = "py-stdlib-sample";
const SAMPLE_LIST_NAME: &str = "sample_modules_314.txt";

const SAMPLE_MODULES: u64 = 115;
const SAMPLE_CODE_OBJECTS: u64 = 3_567;
const SAMPLE_OBJECTS_OK_FLOOR: u64 = 3_396;
const SAMPLE_OBJECT_PCT_FLOOR: f64 = 95.21;
const SAMPLE_MODULES_EXACT_FLOOR: u64 = 66;
const SAMPLE_LIST_DIGEST: u64 = 0xffa6_a85a_98bf_8108;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn deterministic_sample(population: &[String], take: usize) -> Vec<String> {
    let mut ranked: Vec<(u64, &str)> = population
        .iter()
        .map(|module: &String| (fnv1a64(module.as_bytes()), module.as_str()))
        .collect();
    ranked.sort_unstable();
    let mut chosen: Vec<String> = ranked
        .into_iter()
        .take(take)
        .map(|(_, module): (u64, &str)| module.to_owned())
        .collect();
    chosen.sort_unstable();
    chosen
}

fn sample_digest(sample: &[String]) -> u64 {
    fnv1a64(sample.join("\n").as_bytes())
}

fn selected_sample() -> Vec<String> {
    let (full, _pinned): (Vec<String>, Vec<String>) = module_lists();
    let take: usize = usize::try_from(SAMPLE_MODULES).expect("sample size fits usize");
    assert!(
        full.len() >= take,
        "the {FULL_POPULATION} list carries {} module paths, fewer than the {SAMPLE_MODULES} the \
         {SAMPLE_POPULATION} slice draws from it",
        full.len()
    );
    deterministic_sample(&full, take)
}

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
        "this test compares the published bars against the constants this file pins. It decompiles \
         nothing and recompiles nothing, so it proves the documents and this crate name the same \
         numbers, not that either number is the one a real interpreter measures. The measurements \
         live in `sampled_stdlib_recompile_equivalence_gate` ({SAMPLE_POPULATION}, unignored) and \
         `full_stdlib_recompile_equivalence_gate` ({FULL_POPULATION}, ignored by default)."
    );
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
fn the_stdlib_sample_is_drawn_by_module_name_hash_and_pinned_by_digest() {
    let (full, _pinned): (Vec<String>, Vec<String>) = module_lists();
    let take: usize = usize::try_from(SAMPLE_MODULES).expect("sample size fits usize");
    let sample: Vec<String> = deterministic_sample(&full, take);

    let sample_count: u64 = u64::try_from(sample.len()).expect("sample count fits u64");
    assert_eq!(
        sample_count, SAMPLE_MODULES,
        "the {SAMPLE_POPULATION} slice drew {sample_count} module paths, not {SAMPLE_MODULES}"
    );

    let reversed: Vec<String> = full.iter().rev().cloned().collect();
    assert_eq!(
        deterministic_sample(&reversed, take),
        sample,
        "reversing the {FULL_POPULATION} list changed which modules the {SAMPLE_POPULATION} slice \
         selects, so the selection reads iteration order somewhere instead of hashing the module \
         name, and two machines could measure two different populations under one floor"
    );
    assert_eq!(
        deterministic_sample(&full, take),
        sample,
        "two draws from the same list disagree, so the {SAMPLE_POPULATION} selection is not a pure \
         function of the committed module names"
    );

    let digest: u64 = sample_digest(&sample);
    assert_eq!(
        digest, SAMPLE_LIST_DIGEST,
        "the {SAMPLE_POPULATION} slice now digests to {digest:#018x}, not the pinned \
         {SAMPLE_LIST_DIGEST:#018x}. The slice is a function of the committed {FULL_POPULATION} \
         list, so this fires when that list changed; the floors below were measured against the old \
         slice and mean nothing against a new one. Re-measure the slice and re-pin its denominator \
         and its digest together, never the digest alone"
    );

    let full_set: BTreeSet<&str> = full.iter().map(String::as_str).collect();
    let stray: Vec<&str> = sample
        .iter()
        .map(String::as_str)
        .filter(|module: &&str| !full_set.contains(module))
        .collect();
    assert!(
        stray.is_empty(),
        "{} {SAMPLE_POPULATION} modules are not members of the {FULL_POPULATION} list, so the slice \
         does not sample the published population: {stray:?}",
        stray.len()
    );

    assert!(
        sample.len() < full.len(),
        "the {SAMPLE_POPULATION} slice draws {} of the {FULL_POPULATION} list's {} module paths; a \
         slice the size of the whole population would let the sampled floor be read as the \
         published figure",
        sample.len(),
        full.len()
    );

    let object_share: f64 = (SAMPLE_CODE_OBJECTS as f64) * 100.0 / (FULL_CODE_OBJECTS as f64);
    let module_share: f64 = (SAMPLE_MODULES as f64) * 100.0 / (FULL_MODULES as f64);
    println!(
        "{SAMPLE_POPULATION} covers {SAMPLE_MODULES} / {FULL_MODULES} modules ({module_share:.2}%) \
         and {SAMPLE_CODE_OBJECTS} / {FULL_CODE_OBJECTS} code objects ({object_share:.2}%) of the \
         published {FULL_POPULATION} population, digest {SAMPLE_LIST_DIGEST:#018x}"
    );
}

#[test]
fn sampled_stdlib_recompile_equivalence_gate() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the {SAMPLE_POPULATION} gate \
             measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14 interpreter found (uv python find 3.14 / known install paths). This \
             gate is the running measurement behind the published {FULL_POPULATION} figure of \
             {FULL_OBJECTS_OK_FLOOR}/{FULL_CODE_OBJECTS} code objects, so its absence fails the run \
             rather than passing it. Install one with `uv python install 3.14`."
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
        "resolved interpreter at {} is {maj}.{min}, not 3.14; the {FULL_POPULATION} list the \
         {SAMPLE_POPULATION} slice is drawn from is 3.14-specific",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );

    let sample: Vec<String> = selected_sample();
    let sample_count: u64 = u64::try_from(sample.len()).expect("sample count fits u64");
    assert_eq!(
        sample_count, SAMPLE_MODULES,
        "the {SAMPLE_POPULATION} slice drew {sample_count} module paths, not {SAMPLE_MODULES}"
    );
    let digest: u64 = sample_digest(&sample);
    assert_eq!(
        digest, SAMPLE_LIST_DIGEST,
        "the {SAMPLE_POPULATION} slice digests to {digest:#018x}, not the pinned \
         {SAMPLE_LIST_DIGEST:#018x}, so this run would measure a different population than the one \
         the floors below were measured against"
    );

    let scratch: PathBuf = workspace_target().join(SAMPLE_SCRATCH_DIR);
    fs::create_dir_all(&scratch)
        .unwrap_or_else(|e: std::io::Error| panic!("create {}: {e}", scratch.display()));
    let modules: PathBuf = scratch.join(SAMPLE_LIST_NAME);
    let mut rendered: String = sample.join("\n");
    rendered.push('\n');
    fs::write(&modules, rendered.as_bytes())
        .unwrap_or_else(|e: std::io::Error| panic!("write {}: {e}", modules.display()));

    let run: HarnessRun = run_measure(&python, &disrobe, &lib, &modules);
    println!("=== SAMPLED STDLIB RECOMPILE-EQUIVALENCE GATE ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!("sample list : {}", modules.display());
    println!(
        "this measures a {SAMPLE_MODULES} of {FULL_MODULES} module slice of the published \
         {FULL_POPULATION} population, selected by a hash of each committed module name so the same \
         slice is drawn on every run and every platform. Its floors are its own. It is not the \
         published {FULL_POPULATION} figure and must never be quoted as one; \
         `full_stdlib_recompile_equivalence_gate` measures that."
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
        population_line(SAMPLE_POPULATION, m.objects_ok, m.code_objects, m.modules)
    );
    println!(
        "population {SAMPLE_POPULATION}: whole-module exact {} / {} ({:.2}%), sibling-count \
         collisions {}, measured on CPython {}",
        m.modules_exact, m.modules, m.module_pct, m.sibling_collisions, m.cpython_version
    );

    assert_eq!(
        m.listed_modules, SAMPLE_MODULES,
        "the harness read {} module paths from the {SAMPLE_POPULATION} slice, not {SAMPLE_MODULES}",
        m.listed_modules
    );
    assert_eq!(
        m.missing_from_lib, 0,
        "{} of the {SAMPLE_MODULES} sampled modules are absent from this interpreter's Lib, so this \
         run cannot measure the slice the floors were pinned against; the denominator was pinned on \
         CPython {PINNED_CPYTHON}, and an interpreter that ships a different Lib needs a fresh \
         measurement plus a re-pinned denominator, never a lowered floor",
        m.missing_from_lib
    );
    assert_eq!(
        m.modules, SAMPLE_MODULES,
        "only {} of the {SAMPLE_MODULES} sampled modules were measured; a run that inspects fewer \
         modules must score worse, not measure itself against a smaller population",
        m.modules
    );
    assert_eq!(
        m.code_objects, SAMPLE_CODE_OBJECTS,
        "the {SAMPLE_POPULATION} denominator is pinned by equality: this run walked {} code \
         objects, the slice measures {SAMPLE_CODE_OBJECTS} (CPython {PINNED_CPYTHON}, measured \
         {}). A different denominator is a different population, so re-measure and re-pin both \
         halves of the fraction",
        m.code_objects, m.cpython_version
    );
    assert!(
        m.objects_ok >= SAMPLE_OBJECTS_OK_FLOOR,
        "{SAMPLE_POPULATION} per-code-object recompile-equivalence regressed: {} / {} recovered, \
         floor {SAMPLE_OBJECTS_OK_FLOOR} / {SAMPLE_CODE_OBJECTS} ({SAMPLE_OBJECT_PCT_FLOOR}%) on \
         CPython {}. This slice is a fifth of the published {FULL_POPULATION} population, so a drop \
         here is a drop there",
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
    assert!(
        m.object_pct >= SAMPLE_OBJECT_PCT_FLOOR,
        "{SAMPLE_POPULATION} measured {:.2}%, below the pinned {SAMPLE_OBJECT_PCT_FLOOR}% ({} / {} \
         on {} modules, CPython {})",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );
    assert!(
        m.modules_exact >= SAMPLE_MODULES_EXACT_FLOOR,
        "{SAMPLE_POPULATION} whole-module exact recovery regressed: {} / {} modules came back with \
         every code object equivalent, floor {SAMPLE_MODULES_EXACT_FLOOR} / {SAMPLE_MODULES}",
        m.modules_exact,
        m.modules
    );
    assert!(
        m.code_objects < FULL_CODE_OBJECTS && m.modules < FULL_MODULES,
        "this run measured {} code objects over {} modules, which is not smaller than the \
         {FULL_POPULATION} population it samples; a slice that grew into the whole would let the \
         sampled floor stand in for the published figure",
        m.code_objects,
        m.modules
    );
    assert!(
        m.code_objects != PINNED_CODE_OBJECTS && m.modules != PINNED_MODULES,
        "this run measured the {PINNED_POPULATION} population, not the {SAMPLE_POPULATION} slice; \
         the three must never be measured as one"
    );
}

#[test]
#[ignore = "measures the whole 574-module CPython 3.14 stdlib through the real CLI; about four \
            minutes against a debug CLI and less against a release one. No workflow runs it today, \
            so the published full-stdlib figure is re-derived in CI only through the \
            115-module slice in `sampled_stdlib_recompile_equivalence_gate`. Drive the whole \
            population with `cargo test -p disrobe-pass-py-decompile --test \
            full_stdlib_recompile_gate -- --ignored --nocapture`"]
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
