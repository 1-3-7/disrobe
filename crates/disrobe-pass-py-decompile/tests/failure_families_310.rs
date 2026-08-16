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
    BandPopulation, CPYTHON_310, PINNED_MODULE_LIST, population_disagreements, published_band_bar,
    published_population, resolve_band_interpreter,
};
use common::stdlib_measure::{
    FAMILY_HARNESS, FailureFamily, FamilyReport, HarnessRun, PublishedBar, find_disrobe,
    interpreter_stdlib, interpreter_version, manifest_dir, parse_family_report, recovery_document,
    run_family, workspace_target,
};

const BAND_LABEL: &str = "CPython 3.10 (161 of the pinned modules)";
const BAND_CPYTHON: &str = "3.10.20";

const CLUSTER_CEILINGS: &[(&str, u64)] = &[
    ("CODE:LOAD_FAST->SETUP_FINALLY", 22),
    ("CODE:LOAD_FAST->LOAD_GLOBAL", 20),
    ("CODE:JUMP->LOAD_FAST", 15),
    ("CODE:POP_TOP->JUMP", 14),
    ("CODE:GET_ITER->STORE_FAST", 12),
    ("CODE:LOAD_GLOBAL(arg)->LOAD_GLOBAL(arg)", 10),
    ("CODE:SETUP_FINALLY->LOAD_GLOBAL", 11),
    ("CODE:JUMP->LOAD_CONST", 10),
    ("CODE:JUMP_IF_FALSE->POP_TOP", 9),
    ("CODE:LOAD_FAST(arg)->LOAD_FAST(arg)", 10),
    ("SIBLING_MISSING", 8),
    ("SYNTAX_ERR:expected 'except' or 'finally' block", 0),
    ("DECOMPILE_ERR", 0),
];

fn published() -> BandPopulation {
    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar = published_band_bar(&doc, BAND_LABEL);
    published_population(&bar)
}

fn graded(band: &BandPopulation) -> String {
    format!(
        "the recorded CPython 3.10 failure clusters behind the published {} / {} band",
        band.objects_ok, band.code_objects
    )
}

#[test]
fn the_310_band_shortfall_is_named_cluster_by_cluster() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the failure-family table is \
             cut from the same real CLI run the band is, it cannot be derived without it",
            workspace_target().display()
        );
    };

    let band: BandPopulation = published();
    let Some(python): Option<PathBuf> = resolve_band_interpreter(&CPYTHON_310, &graded(&band))
    else {
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
        (3, 10),
        "resolved interpreter at {} is {maj}.{min}, not 3.10",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(FAMILY_HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULE_LIST);
    assert!(
        harness.is_file(),
        "failure-family harness missing at {}",
        harness.display()
    );

    let run: HarnessRun = run_family(&python, &disrobe, &lib, &modules);
    println!("=== CPYTHON 3.10 FAILURE FAMILIES ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("disrobe     : {}", disrobe.display());
    println!("--- family table (stderr) ---\n{}", run.stderr);
    assert!(
        run.success,
        "the failure-family harness exited {:?}; it fails rather than reporting a table whose \
         counts do not sum to the shortfall the same run measured\nstdout:\n{}\nstderr:\n{}",
        run.code, run.stdout, run.stderr
    );

    let report: FamilyReport =
        parse_family_report(&run.stdout).unwrap_or_else(|e: String| panic!("{e}"));
    assert_eq!(
        report.cpython_version, BAND_CPYTHON,
        "the clusters were recorded against CPython {BAND_CPYTHON} and this run measured CPython \
         {}; a different Lib is a different population and needs its own recorded clusters",
        report.cpython_version
    );
    let measured: BandPopulation = BandPopulation {
        objects_ok: report.objects_ok,
        code_objects: report.code_objects,
        modules: report.modules,
    };
    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar = published_band_bar(&doc, BAND_LABEL);
    let disagreements: Vec<String> = population_disagreements(&measured, &bar);
    assert!(
        disagreements.is_empty(),
        "this table must describe the same population the 3.10 band publishes ({} / {} over {} \
         modules), and it described {} / {} over {} modules: {disagreements:?}",
        bar.num,
        bar.den,
        bar.modules,
        report.objects_ok,
        report.code_objects,
        report.modules
    );

    let shortfall: u64 = band.code_objects - band.objects_ok;
    assert_eq!(
        report.failing_objects, shortfall,
        "the 3.10 band leaves {shortfall} code objects unrecovered and this table accounts for {}",
        report.failing_objects
    );
    let charged: u64 = report
        .families
        .iter()
        .map(|row: &FailureFamily| row.objects)
        .sum();
    assert_eq!(
        charged, shortfall,
        "the named clusters charge {charged} code objects while the band leaves {shortfall} \
         unrecovered; a cluster table that does not sum to its own band describes a population \
         nothing measured"
    );

    for &(name, ceiling) in CLUSTER_CEILINGS {
        let charged_here: u64 = report
            .families
            .iter()
            .find(|row: &&FailureFamily| row.family == name)
            .map_or(0, |row: &FailureFamily| row.objects);
        println!("cluster {name}: {charged_here} code objects, recorded ceiling {ceiling}");
        assert!(
            charged_here <= ceiling,
            "the `{name}` cluster grew from the recorded {ceiling} to {charged_here} code objects on \
             CPython {BAND_CPYTHON}; each recorded cluster is a ceiling, so a cluster may shrink \
             to nothing but never widen without a re-recorded table"
        );
    }
}
