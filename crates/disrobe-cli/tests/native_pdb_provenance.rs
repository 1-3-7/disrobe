#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::{Path, PathBuf};

use common::{Run, run_disrobe, temp_dir};
use serde_json::Value;

const EVIDENCE: &str =
    include_str!("../../disrobe-pass-native/tests/fixtures/pdb_cxx_recovery.llvm-pdbutil.txt");

fn fixture_pdb() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("disrobe-pass-native")
        .join("tests")
        .join("fixtures")
        .join("pdb_cxx_recovery.pdb")
}

fn evidence(key: &str) -> &'static str {
    EVIDENCE
        .lines()
        .find_map(|line: &str| line.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("llvm-pdbutil evidence must record {key}"))
}

fn report_for(output_dir: &Path) -> Value {
    let path: PathBuf = output_dir.join("pdb_cxx_recovery.pdb.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read report at {}: {error}", path.display()));
    serde_json::from_str(&text).expect("report must be JSON")
}

fn run_on_fixture(purpose: &str) -> (Run, Value) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(purpose);
    let out: PathBuf = scratch.path().join("report");
    let pdb: PathBuf = fixture_pdb();
    let run: Run = run_disrobe(&[
        "native",
        "pdb",
        pdb.to_str().expect("fixture path is Unicode"),
        "--out",
        out.to_str().expect("scratch path is Unicode"),
    ]);
    assert_eq!(
        run.code, 0,
        "native pdb must succeed on a real MSVC pdb; stderr={}",
        run.stderr
    );
    let report: Value = report_for(&out);
    (run, report)
}

#[test]
fn native_pdb_identity_matches_the_independent_reader() {
    let (_run, report): (Run, Value) = run_on_fixture("native-pdb-identity");
    assert_eq!(report["schema"], "disrobe.native.pdb/v1");
    assert_eq!(report["guid_hex"], evidence("guid_hex"));
    assert_eq!(
        report["age"].as_u64(),
        evidence("age").parse::<u64>().ok(),
        "age must equal the age llvm-pdbutil read"
    );
    assert_eq!(report["dbi_version"], evidence("dbi_version"));
}

#[test]
fn native_pdb_reports_the_compiler_and_linker_versions_the_reference_records() {
    let (run, report): (Run, Value) = run_on_fixture("native-pdb-versions");
    let compilers: &Vec<Value> = report["compilers"]
        .as_array()
        .expect("compilers must be an array");
    let compiler: &Value = compilers
        .iter()
        .find(|row: &&Value| row["version_string"] == evidence("compiler_name"))
        .unwrap_or_else(|| panic!("no record names the reference compiler; got {compilers:?}"));
    assert_eq!(compiler["frontend_version"], evidence("compiler_frontend"));
    assert_eq!(compiler["backend_version"], evidence("compiler_backend"));
    assert_eq!(
        compiler["hot_patch"].as_bool(),
        evidence("compiler_hot_patch").parse::<bool>().ok(),
        "the hot-patch flag must match the reference"
    );
    assert_eq!(compiler["language"], "Cpp");

    let linker: &Value = compilers
        .iter()
        .find(|row: &&Value| row["language"] == "Link")
        .unwrap_or_else(|| panic!("no record carries the linker language; got {compilers:?}"));
    assert_eq!(linker["frontend_version"], evidence("linker_frontend"));
    assert_eq!(linker["backend_version"], evidence("linker_backend"));
    assert!(
        linker["version_string"]
            .as_str()
            .is_some_and(|value: &str| value.contains("LINK")),
        "the linker record must keep the version string the linker wrote"
    );

    assert!(
        run.stdout.contains(evidence("compiler_backend")),
        "the text rendering must print the backend version; stdout={}",
        run.stdout
    );
}

#[test]
fn native_pdb_surfaces_every_recorded_build_string() {
    let (_run, report): (Run, Value) = run_on_fixture("native-pdb-strings");
    let observations: &Vec<Value> = report["observations"]
        .as_array()
        .expect("observations must be an array");
    let values: Vec<&str> = observations
        .iter()
        .filter_map(|row: &Value| row["value"].as_str())
        .collect();
    for key in [
        "working_directory",
        "compiler_tool",
        "source",
        "compiler_pdb",
        "compiler_arguments",
        "object",
        "linker_pdb",
        "linker_arguments",
    ] {
        let expected: &str = evidence(key);
        assert!(
            values.contains(&expected),
            "the report must carry the {key} value the reference records, in full and unredacted"
        );
    }
    for row in observations {
        let hex: &str = row["value_hex"]
            .as_str()
            .expect("value_hex must be a string");
        assert!(
            hex.chars().all(|c: char| c.is_ascii_hexdigit()) && hex.len().is_multiple_of(2),
            "raw bytes must stay recoverable beside the text view"
        );
    }
}

#[test]
fn native_pdb_refuses_input_that_is_not_a_pdb() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("native-pdb-refusal");
    let input: PathBuf = scratch.path().join("not-a.pdb");
    std::fs::write(&input, [0x00_u8; 4096]).expect("write decoy");
    let run: Run = run_disrobe(&[
        "native",
        "pdb",
        input.to_str().expect("scratch path is Unicode"),
    ]);
    assert_ne!(run.code, 0, "a file that is not a PDB must be refused");
    assert!(
        run.stderr.contains("DR-NATIVE-0215"),
        "the refusal must carry its typed code; stderr={}",
        run.stderr
    );
}
