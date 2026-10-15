#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
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
fn the_obfuscated_build_keeps_exactly_the_entry_point_names_its_source_marks() {
    let source: String = source_text("pinned_graph_fixture/receipt_validator.dart");
    let marked: [(&str, &str); 4] = [
        (
            "ReceiptValidator.computeChecksum",
            "@pragma('vm:entry-point')\n  @pragma('vm:never-inline')\n  int computeChecksum(",
        ),
        (
            "ReceiptValidator.formatReceipt",
            "@pragma('vm:entry-point')\n  @pragma('vm:never-inline')\n  String formatReceipt(",
        ),
        (
            "new ReceiptValidator",
            "@pragma('vm:entry-point')\n  const ReceiptValidator(",
        ),
        (
            "new FixtureApp",
            "@pragma('vm:entry-point')\n  const FixtureApp(",
        ),
    ];
    let unmarked: (&str, &str) = (
        "FixtureApp.build",
        "@override\n  Widget build(BuildContext context)",
    );
    for (_, declaration) in marked.iter().chain([&unmarked]) {
        assert!(
            source.contains(declaration),
            "the fixture source must declare {declaration:?}; it is the reference this grade reads"
        );
    }

    let report: AotLiftReport = lift_libapp_aot(&read_sample(
        "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    ))
    .expect("lift the obfuscated sample");
    let names: BTreeSet<String> = report
        .functions
        .iter()
        .filter_map(|f: &DartLiftedFunction| f.name.clone())
        .collect::<BTreeSet<String>>();
    eprintln!(
        "obfuscated build: {} named of {} functions, {} distinct names",
        report.named_function_count,
        report.function_count,
        names.len()
    );
    for (name, _) in marked {
        assert!(
            names.contains(name),
            "{name} is a vm:entry-point the obfuscator must leave named, and the snapshot names its code"
        );
    }
    assert!(
        recovered_names("pinned_graph_fixture/receipt_validator_arm64.so").contains(unmarked.0),
        "the unobfuscated build names {}, so its absence below is the obfuscator's doing",
        unmarked.0
    );
    assert!(
        !names.contains(unmarked.0),
        "{} carries no entry-point pragma, so --obfuscate renamed it and the snapshot cannot name it",
        unmarked.0
    );
    let note: &String = report
        .notes
        .iter()
        .find(|note: &&String| {
            note.contains("instructions-table payloads carry a declared owning function")
        })
        .expect("the obfuscated build must say where its names came from");
    eprintln!("obfuscated build naming: {note}");
}
