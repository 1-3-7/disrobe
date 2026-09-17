#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{AotLiftReport, DartLiftedFunction, lift_libapp_aot};

const RECORDED_APK_NAMED_FLOOR: usize = 5000;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
}

fn read_sample(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = corpus();
    for part in relative.split('/') {
        path = path.join(part);
    }
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("sample {} must be committed: {e}", path.display()))
}

fn source_text(relative: &str) -> String {
    String::from_utf8(read_sample(relative)).expect("the committed Dart source is UTF-8")
}

fn recovered_names(sample: &str) -> BTreeSet<String> {
    let report: AotLiftReport =
        lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
    report
        .functions
        .iter()
        .filter_map(|f: &DartLiftedFunction| f.name.clone())
        .collect::<BTreeSet<String>>()
}

#[test]
fn every_authored_declaration_recovers_from_the_stripped_apk_build() {
    for (sample, source, class) in [
        (
            "pinned_graph_fixture/receipt_validator_arm64.so",
            "pinned_graph_fixture/receipt_validator.dart",
            "ReceiptValidator",
        ),
        (
            "pinned_graph_fixture/voucher_validator_arm64.so",
            "pinned_graph_fixture/voucher_validator.dart",
            "VoucherValidator",
        ),
    ] {
        let text: String = source_text(source);
        assert!(
            text.contains(&format!("class {class} {{")),
            "{source} must declare class {class}; it is the reference this grade reads"
        );

        let mut expected: Vec<String> = Vec::new();
        for member in ["computeChecksum", "formatReceipt"] {
            assert!(
                text.contains(&format!("{member}(")),
                "{source} must declare {member}"
            );
            expected.push(format!("{class}.{member}"));
        }
        assert!(text.contains("Widget build(BuildContext context)"));
        expected.push(String::from("FixtureApp.build"));
        assert!(text.contains("void main() {"));
        expected.push(String::from("main"));
        expected.push(format!("new {class}"));
        expected.push(String::from("new FixtureApp"));

        let names: BTreeSet<String> = recovered_names(sample);
        let mut recovered: usize = 0;
        let mut missing: Vec<&String> = Vec::new();
        for declaration in &expected {
            if names.contains(declaration) {
                recovered += 1;
            } else {
                missing.push(declaration);
            }
        }
        eprintln!(
            "{sample}: authored declarations recovered {recovered}/{} from {} names",
            expected.len(),
            names.len()
        );
        assert!(
            missing.is_empty(),
            "{sample} did not recover the authored declarations {missing:?}"
        );
        assert!(
            names.len() >= RECORDED_APK_NAMED_FLOOR,
            "{sample} recovered only {} names, below the recorded floor of \
             {RECORDED_APK_NAMED_FLOOR}",
            names.len()
        );
    }
}

#[test]
fn the_class_rename_moves_every_recovered_name_with_it() {
    let receipt: BTreeSet<String> =
        recovered_names("pinned_graph_fixture/receipt_validator_arm64.so");
    let voucher: BTreeSet<String> =
        recovered_names("pinned_graph_fixture/voucher_validator_arm64.so");

    for (label, names, present, absent) in [
        ("receipt", &receipt, "ReceiptValidator", "VoucherValidator"),
        ("voucher", &voucher, "VoucherValidator", "ReceiptValidator"),
    ] {
        let owned: Vec<&String> = names
            .iter()
            .filter(|n: &&String| n.starts_with(present) || n.ends_with(present))
            .collect::<Vec<&String>>();
        assert!(
            !owned.is_empty(),
            "the {label} build must recover names qualified by {present}"
        );
        let foreign: Vec<&String> = names
            .iter()
            .filter(|n: &&String| n.contains(absent))
            .collect::<Vec<&String>>();
        assert!(
            foreign.is_empty(),
            "the {label} build recovered {absent} names {foreign:?}; the two builds differ only by \
             the class rename, so a name from the other build means the recovery is not reading \
             this artifact"
        );
        eprintln!(
            "{label} build: {} names qualified by {present}",
            owned.len()
        );
    }
}

#[test]
fn the_obfuscated_build_recovers_no_authored_name_and_names_its_reason() {
    let report: AotLiftReport = lift_libapp_aot(&read_sample(
        "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    ))
    .expect("lift the obfuscated sample");
    let named: usize = report
        .functions
        .iter()
        .filter(|f: &&DartLiftedFunction| f.name.is_some())
        .count();
    assert_eq!(
        named, 0,
        "the obfuscated build must not claim authored names; the precompiler renamed them"
    );
    let reason: &String = report
        .notes
        .iter()
        .find(|note: &&String| note.contains("could not supply offset-to-name coverage"))
        .expect("the obfuscated build must name why it recovers no name");
    eprintln!("obfuscated build refusal: {reason}");
    assert!(
        reason.contains("DR-MOB-"),
        "the refusal must carry its diagnostic code, got {reason}"
    );
}
