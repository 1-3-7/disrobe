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
const AARCH64: &str = "corpus/native/discovery/disc_aarch64.unstripped.elf";
const ARM32: &str = "corpus/native/arch/arm32_forms.elf";
const LINEAGE_COMPLETE_FAMILIES: u64 = 317;

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
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
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

fn run_expecting_refusal(args: &[&str]) -> String {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}",
        binary.display()
    );
    let mut command: Command = Command::new(&binary);
    command.arg("semdiff");
    for arg in args {
        if arg.starts_with("--") {
            command.arg(arg);
        } else {
            command.arg(fixture(arg));
        }
    }
    let output: Output = command
        .env_remove("RUST_LOG")
        .output()
        .expect("semdiff must run");
    assert!(
        !output.status.success(),
        "semdiff {args:?} was expected to refuse but exited 0 with: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_lineage(args: &[&str]) -> Value {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}",
        binary.display()
    );
    let mut command: Command = Command::new(&binary);
    command.arg("semdiff");
    for arg in args {
        command.arg(fixture(arg));
    }
    let output: Output = command
        .arg("--lineage")
        .arg("--limit")
        .arg(FULL_LISTING.to_string())
        .arg("--json")
        .env_remove("RUST_LOG")
        .output()
        .expect("semdiff --lineage must run");
    assert!(
        output.status.success(),
        "semdiff --lineage {args:?} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    parse(&String::from_utf8(output.stdout).expect("lineage json is utf8"))
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
fn two_native_images_of_different_architectures_are_refused_before_pairing() {
    let stderr: String = run_expecting_refusal(&[CLEAN, AARCH64]);
    assert!(
        stderr.contains("DR-CLI-0874"),
        "a cross-architecture pair must be refused by code, saw: {stderr}"
    );
}

#[test]
fn a_second_other_without_lineage_is_refused_rather_than_ignored() {
    let stderr: String = run_expecting_refusal(&[CLEAN, VIRTUALIZED, VIRTUALIZED]);
    assert!(
        stderr.contains("DR-CLI-0872"),
        "extra positional builds must be refused, not silently dropped, saw: {stderr}"
    );
}

#[test]
fn lineage_places_every_anchor_function_in_a_family_across_every_variant() {
    let report: Value = run_lineage(&[CLEAN, CLEAN, VIRTUALIZED]);
    assert_eq!(count(&report, "anchor_functions"), CLEAN_FUNCTIONS);
    assert_eq!(count(&report, "variant_count"), 2);
    assert_eq!(
        count(&report, "families"),
        CLEAN_FUNCTIONS,
        "every anchor function must head a family, even one nothing matched"
    );
    assert_eq!(
        count(&report, "complete_families"),
        LINEAGE_COMPLETE_FAMILIES
    );
    let families: &Vec<Value> = report["family_rows"]
        .as_array()
        .expect("family_rows is an array");
    assert_eq!(
        families.len() as u64,
        CLEAN_FUNCTIONS,
        "the listing must not truncate under an explicit limit"
    );
    for family in families {
        let members: &Vec<Value> = family["members"]
            .as_array()
            .expect("each family lists one member per variant");
        assert_eq!(
            members.len(),
            2,
            "a family must carry a verdict for every variant, present or absent"
        );
        for member in members {
            let matched: bool = member.get("address").is_some();
            let refused: bool = member.get("reason").is_some();
            assert!(
                matched != refused,
                "a member is either matched with an address or absent with a reason, never both or neither: {member:?}"
            );
        }
    }
}

#[test]
fn lineage_refuses_a_variant_whose_architecture_differs_from_the_anchor() {
    let stderr: String = run_expecting_refusal(&[CLEAN, VIRTUALIZED, AARCH64, "--lineage"]);
    assert!(
        stderr.contains("DR-CLI-0874"),
        "a mixed-architecture variant must be refused, saw: {stderr}"
    );
}

#[test]
fn a_native_image_lifts_under_the_language_of_its_own_architecture() {
    let x86: Value = parse(&run_semdiff(CLEAN, CLEAN));
    assert_eq!(
        x86["base_lang"], "native-x86",
        "an x86-64 image must lift as x86"
    );
    let arm: Value = parse(&run_semdiff(ARM32, ARM32));
    assert_eq!(
        arm["base_lang"], "native-arm",
        "an arm image must not inherit the x86 default the native lift used to apply to every architecture"
    );
    assert_ne!(
        x86["base_lang"], arm["base_lang"],
        "two different machine architectures must not report one source language"
    );
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
