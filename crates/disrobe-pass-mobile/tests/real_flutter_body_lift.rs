#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{AotLiftReport, DartLiftedFunction, lift_libapp_aot};

const COMMITTED_SAMPLES: [&str; 4] = [
    "disrobe_sample/libapp_arm64.so",
    "pinned_graph_fixture/receipt_validator_arm64.so",
    "pinned_graph_fixture/receipt_validator_obfuscated_arm64.so",
    "pinned_graph_fixture/voucher_validator_arm64.so",
];

const RECORDED_LIFTED_FLOOR_PERCENT: usize = 70;

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

fn dart_source() -> String {
    String::from_utf8(read_sample("disrobe_sample/disrobe_aot_sample.dart"))
        .expect("the committed Dart source is UTF-8")
}

fn structured_bodies(report: &AotLiftReport) -> Vec<String> {
    report
        .functions
        .iter()
        .filter(|f: &&DartLiftedFunction| f.is_structured())
        .map(DartLiftedFunction::best_pseudo_dart)
        .collect::<Vec<String>>()
}

#[test]
fn source_declared_constructor_literals_recover_as_field_stores() {
    let source: String = dart_source();
    let declared: [(&str, [&str; 3]); 4] = [
        (
            "InventoryItem('widget-alpha', 42, 19.95)",
            ["\"widget-alpha\"", "42", "19.95"],
        ),
        (
            "InventoryItem('gadget-bravo', 0, 149.50)",
            ["\"gadget-bravo\"", "0", "149.5"],
        ),
        (
            "InventoryItem('sprocket-charlie', 7, 2400.00)",
            ["\"sprocket-charlie\"", "7", "2400.0"],
        ),
        (
            "InventoryItem('flange-delta', 130, 4.25)",
            ["\"flange-delta\"", "130", "4.25"],
        ),
    ];
    for (declaration, _) in &declared {
        assert!(
            source.contains(declaration),
            "the committed Dart source must declare {declaration}; it is the reference this grade reads"
        );
    }

    let report: AotLiftReport =
        lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift the sample");
    let main: String = structured_bodies(&report)
        .into_iter()
        .find(|body: &String| body.starts_with("main(") && body.contains("fibonacciStep"))
        .expect("the application main must lift");
    eprintln!("--- main ---\n{main}");

    let stores: Vec<&str> = main
        .lines()
        .map(str::trim)
        .filter(|line: &&str| line.contains(".field@") && line.contains(" = "))
        .collect::<Vec<&str>>();

    let mut recovered: usize = 0;
    let mut total: usize = 0;
    for (declaration, literals) in &declared {
        for literal in literals {
            total += 1;
            let assigned: bool = stores
                .iter()
                .any(|line: &&str| line.ends_with(&format!(" = {literal};")));
            assert!(
                assigned,
                "the source literal {literal} of {declaration} must recover as a field store, got:\n{main}"
            );
            recovered += 1;
        }
    }
    eprintln!("constructor literals recovered as field stores: {recovered}/{total}");
    assert_eq!(
        recovered, total,
        "every literal the Dart source declares must appear in a recovered field store"
    );

    let receivers: usize = declared
        .iter()
        .filter(|(_, literals): &&(&str, [&str; 3])| {
            let name: &str = literals[0];
            stores
                .iter()
                .filter(|line: &&&str| line.ends_with(&format!(" = {name};")))
                .filter_map(|line: &&str| line.split(".field@").next())
                .any(|receiver: &str| receiver.starts_with('v'))
        })
        .count();
    assert_eq!(
        receivers,
        declared.len(),
        "each constructor's field stores must be attributed to the bound allocation, got:\n{main}"
    );
}

#[test]
fn the_backordered_source_predicate_and_the_empty_list_guard_recover() {
    let source: String = dart_source();
    assert!(
        source.contains("if (trackedItems.isEmpty) {") && source.contains("return null;"),
        "the committed Dart source must declare the empty-list guard this grade reads"
    );
    let report: AotLiftReport =
        lift_libapp_aot(&read_sample("disrobe_sample/libapp_arm64.so")).expect("lift the sample");
    let most_valuable: &DartLiftedFunction = report
        .functions
        .iter()
        .find(|f: &&DartLiftedFunction| f.name.as_deref() == Some("WarehouseLedger.mostValuable"))
        .expect("the committed symbol table names mostValuable");
    let body: String = most_valuable.best_pseudo_dart();
    eprintln!("--- mostValuable ---\n{body}");
    assert!(
        body.contains("return null;"),
        "the source `return null;` must recover as a null return, got:\n{body}"
    );
    let guard: &str = body
        .lines()
        .map(str::trim)
        .find(|line: &&str| line.starts_with("if ("))
        .expect("the empty-list guard must render");
    assert!(
        guard.contains(".field@") && guard.contains(" 0"),
        "the emptiness guard must compare a recovered field against zero, not a raw register, got:\n{body}"
    );
}

#[test]
fn every_modelled_arm64_family_is_observed_or_named_unobserved() {
    let families: [(&str, &str); 18] = [
        ("add", " + "),
        ("subtract", " - "),
        ("multiply", " * "),
        ("double divide", " / "),
        ("truncating divide", " ~/ "),
        ("remainder", " % "),
        ("bitwise and", " & "),
        ("bitwise or", " | "),
        ("bitwise xor", " ^ "),
        ("shift left", " << "),
        ("arithmetic shift right", " >> "),
        ("logical shift right", " >>> "),
        ("bitwise not", "~"),
        ("negate", "-v"),
        ("smi untag", "smiUntag("),
        ("smi tag", "smiTag("),
        ("signed truncation", ".toSigned("),
        ("unsigned truncation", ".toUnsigned("),
    ];
    let unobserved: [(&str, &str); 3] = [
        (
            "absolute",
            "gen_snapshot emits fabs only inside loop bodies in this corpus, where the merge-conservative tracker holds no operand",
        ),
        (
            "square root",
            "fsqrt appears in the corpus only inside loop bodies, where the merge-conservative tracker holds no operand",
        ),
        (
            "maximum and minimum",
            "fmax and fmin appear in the corpus only inside loop bodies, where the merge-conservative tracker holds no operand",
        ),
    ];
    let unobserved_needles: [(&str, &str); 3] = [
        ("absolute", ".abs()"),
        ("square root", "sqrt("),
        ("maximum and minimum", "max("),
    ];

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        for body in structured_bodies(&report) {
            for (family, needle) in families.iter().chain(unobserved_needles.iter()) {
                let found: usize = if *family == "bitwise not" {
                    body.matches('~').count() - body.matches("~/").count()
                } else {
                    body.matches(needle).count()
                };
                *counts.entry(family).or_default() += found;
            }
        }
    }
    for (family, count) in &counts {
        eprintln!("{family}: {count}");
    }
    for (family, _) in &families {
        assert!(
            counts.get(family).copied().unwrap_or(0) > 0,
            "the {family} family must be exercised by a lifted body in the committed corpus, or be moved to the named unobserved list with its reason"
        );
    }
    for (family, reason) in &unobserved {
        assert_eq!(
            counts.get(family).copied().unwrap_or(0),
            0,
            "{family} is recorded as unobserved because {reason}; it is now observed, so move it to the graded list"
        );
    }
    assert!(
        !counts.contains_key("select"),
        "the family table and the observation map must not drift"
    );
}

#[test]
fn an_indirect_branch_keeps_its_function_on_the_flat_disassembly_path() {
    let mut with_indirect: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        for function in &report.functions {
            let indirect: bool = function
                .unlifted_arm64
                .iter()
                .any(|entry| entry.text.starts_with("br "));
            if !indirect {
                continue;
            }
            with_indirect += 1;
            assert!(
                !function.is_structured(),
                "{sample} structured {:?} even though it branches through a register; the jump-table \
                 and register-dispatch families are not modelled and must not reach a lifted body",
                function.name
            );
        }
    }
    eprintln!(
        "functions carrying a register-indirect branch across the committed corpus: {with_indirect}"
    );
    assert!(
        with_indirect > 0,
        "the committed corpus must contain register-indirect branches for this boundary to mean anything"
    );
}

#[test]
fn the_conditional_select_family_renders_a_ternary_in_a_real_body() {
    let mut ternaries: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        for body in structured_bodies(&report) {
            ternaries += body.matches(" ? ").count();
        }
    }
    eprintln!("conditional-select renderings across the committed corpus: {ternaries}");
    assert!(
        ternaries > 0,
        "the ARM64 conditional-select family must render as a Dart conditional expression in at least one real body"
    );
}

#[test]
fn body_statements_lift_and_every_unlifted_instruction_stays_marked() {
    let mut lifted_total: usize = 0;
    let mut unlifted_total: usize = 0;
    for sample in COMMITTED_SAMPLES {
        let report: AotLiftReport =
            lift_libapp_aot(&read_sample(sample)).expect("lift committed Dart sample");
        let statements: usize = report.lifted_statements + report.unlifted_statements;
        assert!(
            statements > 0,
            "{sample} must render structured bodies with body statements"
        );
        assert!(
            report.unlifted_statements > 0,
            "{sample} must keep an explicit marker on the instructions it could not lift"
        );
        let percent: usize = report.lifted_statements.saturating_mul(100) / statements;
        eprintln!(
            "{sample}: lifted {}/{} body statements ({percent}%), returns={} field stores={} conditions={}",
            report.lifted_statements,
            statements,
            report.recovered_return_expressions,
            report.recovered_field_stores,
            report.recovered_conditions,
        );
        assert!(
            percent >= RECORDED_LIFTED_FLOOR_PERCENT,
            "{sample} lifted {percent}% of its body statements, below the recorded floor of {RECORDED_LIFTED_FLOOR_PERCENT}%"
        );
        assert!(
            report.recovered_return_expressions > 0 && report.recovered_field_stores > 0,
            "{sample} must recover return expressions and field stores"
        );
        for function in &report.functions {
            if !function.is_structured() {
                continue;
            }
            assert!(
                function.lifted_statement_count + function.unlifted_statement_count
                    <= function.unlifted_arm64.len(),
                "{sample} accounted for more body statements than the artifact carries in {:?}",
                function.name
            );
        }
        lifted_total += report.lifted_statements;
        unlifted_total += report.unlifted_statements;
    }
    eprintln!(
        "committed corpus: lifted {lifted_total} of {} body statements",
        lifted_total + unlifted_total
    );
}
