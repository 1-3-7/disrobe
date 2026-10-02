#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const RUN_TIMEOUT: Duration = Duration::from_secs(10);

struct Lane {
    fixtures: &'static str,
    interpreter: &'static str,
    min_cases: usize,
    behaviour_only: &'static [&'static str],
}

const LANE_314: Lane = Lane {
    fixtures: "tests/fixtures/structuring_behaviour",
    interpreter: "3.14",
    min_cases: 18,
    behaviour_only: &["for_try_break_first", "for_try_break_nested_for"],
};

const LANE_312: Lane = Lane {
    fixtures: "tests/fixtures/structuring_behaviour_312",
    interpreter: "3.12",
    min_cases: 2,
    behaviour_only: &["bottom_guarded_continue_loop"],
};

fn interpreter(lane: &Lane) -> BandInterpreter {
    let version: &str = lane.interpreter;
    resolve_band(&[version], &[])
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "the strict structuring behaviour set requires CPython {version} \
                 (uv python install {version})"
            )
        })
}

fn cases(lane: &Lane) -> Vec<(String, String)> {
    let dir: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(lane.fixtures);
    let mut cases: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", dir.display()))
        .map(|entry: std::io::Result<std::fs::DirEntry>| entry.expect("fixture entry").path())
        .filter(|path: &PathBuf| path.extension().is_some_and(|ext| ext == "py"))
        .map(|path: PathBuf| {
            let name: String = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("fixture names are UTF-8")
                .to_owned();
            let source: String = std::fs::read_to_string(&path)
                .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
            (name, source)
        })
        .collect();
    cases.sort();
    assert!(
        cases.len() >= lane.min_cases,
        "the strict set {} holds {} programs, fewer than the {} pinned shapes",
        lane.fixtures,
        cases.len(),
        lane.min_cases
    );
    cases
}

fn run(python: &Path, script: &Path) -> Result<String, String> {
    let output: ToolOutput = tool_output(CommandSpec::new(python, RUN_TIMEOUT).arg(script))
        .map_err(|error: disrobe_testkit::ToolError| error.to_string())?;
    if output.timed_out {
        return Err(format!("timed out after {RUN_TIMEOUT:?}"));
    }
    if !output.success {
        return Err(output.stderr_text().trim().to_owned());
    }
    Ok(output.stdout_text().replace("\r\n", "\n"))
}

fn grade(
    lane: &Lane,
    interp: &BandInterpreter,
    dir: &Path,
    name: &str,
    source: &str,
) -> Option<String> {
    let original: PathBuf = dir.join(format!("{name}.orig.py"));
    std::fs::write(&original, source).expect("write original");
    let expected: String = run(&interp.path, &original)
        .unwrap_or_else(|error: String| panic!("{name}: the fixture must run: {error}"));
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(interp, source, name, dir);
    if recovered.is_empty() || recovered.contains("decompile-error") {
        return Some(format!(
            "{name}: no source was recovered: {outcome:?}\n{recovered}"
        ));
    }
    if !lane.behaviour_only.contains(&name) && !matches!(outcome, BandOutcome::RecompileEquiv) {
        return Some(format!(
            "{name}: the recovered source does not recompile to equivalent bytecode: \
             {outcome:?}\n{recovered}"
        ));
    }
    let recovered_path: PathBuf = dir.join(format!("{name}.run.py"));
    std::fs::write(&recovered_path, &recovered).expect("write recovered");
    let actual: Result<String, String> = run(&interp.path, &recovered_path);
    (actual.as_deref() != Ok(expected.as_str())).then(|| {
        format!("{name}: expected {expected:?}, recovered program gave {actual:?}\n{recovered}")
    })
}

fn assert_lane_recovers(lane: &Lane, scratch: &str) {
    let interp: BandInterpreter = interpreter(lane);
    let dir: PathBuf = band_scratch(scratch);
    let failures: Vec<String> = cases(lane)
        .iter()
        .filter_map(|(name, source): &(String, String)| grade(lane, &interp, &dir, name, source))
        .collect();
    assert!(
        failures.is_empty(),
        "{} pinned structuring shapes regressed on CPython {}:\n{}",
        failures.len(),
        lane.interpreter,
        failures.join("\n=====\n")
    );
}

#[test]
fn every_pinned_structuring_shape_recovers_to_identical_behaviour() {
    assert_lane_recovers(&LANE_314, "structuring_behaviour_strict");
}

#[test]
fn every_pinned_312_structuring_shape_recovers_to_identical_behaviour() {
    assert_lane_recovers(&LANE_312, "structuring_behaviour_strict_312");
}

#[test]
fn every_behaviour_only_case_names_a_fixture() {
    for lane in [&LANE_314, &LANE_312] {
        let names: Vec<String> = cases(lane).into_iter().map(|(name, _)| name).collect();
        for name in lane.behaviour_only {
            assert!(
                names.iter().any(|candidate: &String| candidate == name),
                "{name} is exempt from the recompile check but no fixture in {} carries it",
                lane.fixtures
            );
        }
    }
}

#[test]
fn a_recovery_that_drops_a_break_is_caught() {
    let interp: BandInterpreter = interpreter(&LANE_314);
    let dir: PathBuf = band_scratch("structuring_behaviour_strict_mutation");
    let (name, source): (String, String) = cases(&LANE_314)
        .into_iter()
        .find(|(name, _)| name == "ternary_then_break")
        .expect("the ternary_then_break fixture is pinned");
    let (_, recovered): (BandOutcome, String) =
        recompile_equiv_inline(&interp, &source, &name, &dir);
    let mutated: String = recovered.replacen("break", "pass", 1);
    assert_ne!(mutated, recovered, "the recovery must contain the break");
    let original_path: PathBuf = dir.join("mutant.orig.py");
    std::fs::write(&original_path, &source).expect("write");
    let mutated_path: PathBuf = dir.join("mutant.mut.py");
    std::fs::write(&mutated_path, &mutated).expect("write");
    assert_ne!(
        run(&interp.path, &original_path),
        run(&interp.path, &mutated_path)
    );
}
