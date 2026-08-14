#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const CLEAN: &str = "corpus/native/obfuscators/guardian-rs/sample.clean.exe";
const VIRTUALIZED: &str = "corpus/native/obfuscators/guardian-rs/sample.virtualized.exe";
const WASM: &str = "corpus/wasm/wat/function_refs.wasm";

const CLEAN_FUNCTIONS: u64 = 383;
const CLEAN_SELF_MATCHED: u64 = 319;
const CLEAN_SELF_LEAF_EXACT: u64 = 44;
const CLEAN_SELF_PROPAGATED: u64 = 275;
const CLEAN_VS_VIRTUALIZED_MATCHED: u64 = 317;
const CLEAN_VS_VIRTUALIZED_NAMED_CHANGES: u64 = 2;
const WASM_FUNCTIONS: u64 = 2;
const FULL_LISTING: usize = 100_000;

const KNOWN_REASONS: [&str; 6] = [
    "no-candidate",
    "ambiguous",
    "round-budget-exhausted",
    "function-count-cap-exceeded",
    "duplicate-address",
    "source-language-mismatch",
];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn cli_binary() -> PathBuf {
    let mut binary: PathBuf = workspace_root();
    binary.push("target");
    binary.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    binary.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    binary
}

fn fixture(relative: &str) -> PathBuf {
    let mut path: PathBuf = workspace_root();
    path.push(relative);
    assert!(
        path.exists(),
        "committed fixture missing at {}; this test grades against real artifacts and must not be skipped",
        path.display()
    );
    path
}

fn run_semdiff(base: &str, other: &str) -> String {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli --bin disrobe` first",
        binary.display()
    );
    let base_path: PathBuf = fixture(base);
    let other_path: PathBuf = fixture(other);
    let output: Output = Command::new(&binary)
        .arg("semdiff")
        .arg(&base_path)
        .arg(&other_path)
        .arg("--limit")
        .arg(FULL_LISTING.to_string())
        .arg("--json")
        .env_remove("RUST_LOG")
        .output()
        .expect("semdiff must run");
    assert!(
        output.status.success(),
        "semdiff {base} {other} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("semdiff json is utf8")
}

fn parse(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("semdiff --json emits one json document")
}

fn count(report: &Value, key: &str) -> u64 {
    report[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is a number in the semdiff report"))
}

fn reasons(report: &Value) -> BTreeSet<String> {
    ["unmatched_base", "unmatched_other"]
        .iter()
        .flat_map(|side: &&str| {
            report[*side]
                .as_array()
                .expect("unmatched sides are arrays")
                .iter()
                .map(|row: &Value| {
                    row["reason"]
                        .as_str()
                        .expect("every refusal carries a reason")
                        .to_owned()
                })
        })
        .collect()
}

#[test]
fn a_build_paired_with_itself_never_pairs_two_different_addresses() {
    let report: Value = parse(&run_semdiff(CLEAN, CLEAN));
    let pairs: &Vec<Value> = report["matches"]
        .as_array()
        .expect("matches is an array of pairs");
    assert_eq!(
        pairs.len() as u64,
        count(&report, "matched"),
        "the invariant below must see every pair, not a truncated listing"
    );
    assert!(
        !pairs.is_empty(),
        "a build paired with itself must produce at least one pair"
    );
    let mismatched: Vec<&Value> = pairs
        .iter()
        .filter(|pair: &&Value| pair["base_address"] != pair["other_address"])
        .collect();
    assert!(
        mismatched.is_empty(),
        "pairing a build with itself put {} functions at different addresses, first {:?}",
        mismatched.len(),
        mismatched.first()
    );
    assert_eq!(
        count(&report, "named_change_count"),
        0,
        "the name-keyed diff of a build against itself must be empty"
    );
}

#[test]
fn the_measured_self_pairing_of_a_real_pe_holds() {
    let report: Value = parse(&run_semdiff(CLEAN, CLEAN));
    assert_eq!(count(&report, "base_functions"), CLEAN_FUNCTIONS);
    assert_eq!(count(&report, "other_functions"), CLEAN_FUNCTIONS);
    assert_eq!(count(&report, "matched"), CLEAN_SELF_MATCHED);
    assert_eq!(count(&report["tiers"], "leaf_exact"), CLEAN_SELF_LEAF_EXACT);
    assert_eq!(count(&report["tiers"], "propagated"), CLEAN_SELF_PROPAGATED);
    let tier_total: u64 = count(&report["tiers"], "leaf_exact")
        + count(&report["tiers"], "symbolic_summary")
        + count(&report["tiers"], "propagated");
    assert_eq!(
        tier_total,
        count(&report, "matched"),
        "every pair must be attributed to exactly one tier"
    );
    assert!(
        count(&report, "rounds_run") <= count(&report, "max_propagation_rounds"),
        "propagation must stay inside its round budget"
    );
}

#[test]
fn two_builds_of_one_program_are_distinguished_and_every_refusal_is_typed() {
    let report: Value = parse(&run_semdiff(CLEAN, VIRTUALIZED));
    assert_eq!(
        count(&report, "matched"),
        CLEAN_VS_VIRTUALIZED_MATCHED,
        "the virtualized build must pair fewer functions than the clean build pairs with itself"
    );
    assert!(
        count(&report, "matched") < CLEAN_SELF_MATCHED,
        "a virtualized build must not pair as well as an identical one"
    );
    assert_eq!(
        count(&report, "named_change_count"),
        CLEAN_VS_VIRTUALIZED_NAMED_CHANGES
    );
    let seen: BTreeSet<String> = reasons(&report);
    assert!(
        !seen.is_empty(),
        "a partial pairing must report why the rest were refused"
    );
    for reason in &seen {
        assert!(
            KNOWN_REASONS.contains(&reason.as_str()),
            "unknown refusal reason {reason}; the CLI mapping and disrobe-semdiff have drifted"
        );
    }
}

#[test]
fn inputs_that_lift_to_different_languages_are_refused_by_name() {
    let report: Value = parse(&run_semdiff(WASM, CLEAN));
    assert_eq!(report["base_lang"], "wasm");
    assert_eq!(report["other_lang"], "native-x86");
    assert_eq!(count(&report, "base_functions"), WASM_FUNCTIONS);
    assert_eq!(
        count(&report, "matched"),
        0,
        "functions from different source languages must never pair"
    );
    let seen: BTreeSet<String> = reasons(&report);
    assert!(
        seen.contains("source-language-mismatch"),
        "a cross-language pairing must say so; saw {seen:?}"
    );
    let first: &Value = &report["unmatched_base"][0];
    assert_eq!(first["base_lang"], "wasm");
    assert_eq!(first["other_lang"], "native-x86");
}

#[test]
fn the_report_is_byte_identical_across_runs() {
    let first: String = run_semdiff(CLEAN, VIRTUALIZED);
    let second: String = run_semdiff(CLEAN, VIRTUALIZED);
    assert_eq!(
        first, second,
        "semdiff output must be deterministic for the same inputs"
    );
}
