#![allow(
    clippy::absurd_extreme_comparisons,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

pub mod common;

use std::path::PathBuf;

use common::{JvmVerifier, VerifyScope, lines_with_prefix, parse_metric};
use disrobe_pass_jvm::assemble_jar;
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};

const COMMITTED_DEXES: &[(&str, &[u8])] = &[
    (
        "EdgeCases.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex"),
    ),
    (
        "EdgeCasesKt.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex"),
    ),
    (
        "Hello.dex",
        include_bytes!("../../../corpus/jvm/dex/Hello.dex"),
    ),
];

const VERIFY_CLEAN_CLASS_FLOOR: usize = 102;

const LIFTER_VERIFY_FAIL_CEILING: usize = 0;

const BODY_VERIFY_CLEAN_FLOOR: usize = 317;

const BODY_VERIFY_FAIL_CEILING: usize = 0;

struct VerifyCounts {
    clean_classes: usize,
    lifter_fail_classes: usize,
    link_skipped_classes: usize,
    methods_clean: usize,
    methods_in_failed_classes: usize,
    body_clean: usize,
    body_fail: usize,
    errors: Vec<String>,
}

fn counts_from(stdout: &str) -> VerifyCounts {
    let mut errors: Vec<String> = lines_with_prefix(stdout, "VERIFY ");
    errors.extend(lines_with_prefix(stdout, "BODYVERIFY "));
    VerifyCounts {
        clean_classes: parse_metric(stdout, "verify_clean_classes="),
        lifter_fail_classes: parse_metric(stdout, "lifter_verify_fail_classes="),
        link_skipped_classes: parse_metric(stdout, "link_skipped_classes="),
        methods_clean: parse_metric(stdout, "methods_clean="),
        methods_in_failed_classes: parse_metric(stdout, "methods_lifter_fail="),
        body_clean: parse_metric(stdout, "body_clean="),
        body_fail: parse_metric(stdout, "body_fail="),
        errors,
    }
}

#[test]
fn recovered_dalvik_bodies_pass_the_real_jvm_verifier() {
    let verifier: JvmVerifier = match JvmVerifier::prepare(&format!(
        "disrobe_dalvik_verifier_gate_{}",
        std::process::id()
    )) {
        Ok(v) => v,
        Err(why) => {
            eprintln!(
                "SKIP dalvik verifier gate: {why}; \
                 the headline verifier-clean number cannot be attested in this environment"
            );
            return;
        }
    };

    let mut total_clean: usize = 0;
    let mut total_lifter_fail: usize = 0;
    let mut total_link_skipped: usize = 0;
    let mut total_methods_clean: usize = 0;
    let mut total_methods_in_failed: usize = 0;
    let mut total_body_clean: usize = 0;
    let mut total_body_fail: usize = 0;
    let mut all_errors: Vec<String> = Vec::new();

    for (label, dex_bytes) in COMMITTED_DEXES {
        let result: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate dex");
        let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
        let jar_path: PathBuf = verifier.write_jar(label, &jar);

        let counts: VerifyCounts =
            counts_from(&verifier.run(VerifyScope::Classes, jar_path.as_path()));
        let verifiable: usize = counts.clean_classes + counts.lifter_fail_classes;
        let pct: f64 = counts.clean_classes as f64 * 100.0 / verifiable.max(1) as f64;
        eprintln!(
            "DALVIK VERIFY {label}: clean={} lifter_fail={} link_skipped={} \
             ({pct:.1}% of verifiable classes pass -Xverify:all); methods_in_clean_classes={} methods_in_failed_classes={} \
             body_clean={} body_fail={}",
            counts.clean_classes,
            counts.lifter_fail_classes,
            counts.link_skipped_classes,
            counts.methods_clean,
            counts.methods_in_failed_classes,
            counts.body_clean,
            counts.body_fail
        );
        total_clean += counts.clean_classes;
        total_lifter_fail += counts.lifter_fail_classes;
        total_link_skipped += counts.link_skipped_classes;
        total_methods_clean += counts.methods_clean;
        total_methods_in_failed += counts.methods_in_failed_classes;
        total_body_clean += counts.body_clean;
        total_body_fail += counts.body_fail;
        all_errors.extend(counts.errors);
    }

    let verifiable: usize = total_clean + total_lifter_fail;
    let class_pct: f64 = total_clean as f64 * 100.0 / verifiable.max(1) as f64;
    eprintln!(
        "DALVIK VERIFY TOTAL: verifier_clean_classes={total_clean} lifter_verify_fail_classes={total_lifter_fail} \
         link_skipped_classes={total_link_skipped} \
         => {class_pct:.1}% of verifiable classes pass the real JVM verifier on the committed dex corpus \
         (methods in clean classes={total_methods_clean}, in failed classes={total_methods_in_failed}); \
         RE-HOSTED BODY VERIFY: body_clean={total_body_clean} body_fail={total_body_fail} \
         (every non-stub recovered method body re-hosted into an Object carrier and run through -Xverify:all)"
    );
    for e in &all_errors {
        eprintln!("  {e}");
    }
    assert!(
        total_clean >= VERIFY_CLEAN_CLASS_FLOOR,
        "verifier-clean classes {total_clean} fell below floor {VERIFY_CLEAN_CLASS_FLOOR}; \
         the dalvik lifter regressed (fewer recovered bodies pass the real JVM verifier)"
    );
    assert!(
        total_lifter_fail <= LIFTER_VERIFY_FAIL_CEILING,
        "genuine lifter verify failures {total_lifter_fail} exceeded ceiling {LIFTER_VERIFY_FAIL_CEILING}; \
         the lifter started emitting malformed bytecode the JVM rejects:\n{}",
        all_errors.join("\n")
    );
    assert!(
        total_body_clean >= BODY_VERIFY_CLEAN_FLOOR,
        "re-hosted verifier-clean method bodies {total_body_clean} fell below floor {BODY_VERIFY_CLEAN_FLOOR}; \
         the dalvik lifter recovered fewer real bodies that pass the per-method -Xverify:all carrier"
    );
    assert!(
        total_body_fail <= BODY_VERIFY_FAIL_CEILING,
        "re-hosted method bodies that the JVM verifier rejects {total_body_fail} exceeded ceiling {BODY_VERIFY_FAIL_CEILING}; \
         the lifter emitted a real body the verifier rejects:\n{}",
        all_errors.join("\n")
    );
    assert!(
        verifiable >= 90,
        "expected the committed corpus to submit >=90 verifiable classes to the JVM, got {verifiable}"
    );
}

#[test]
fn published_dalvik_verifier_bar_matches_the_floors_this_gate_enforces() {
    const BAR: &str = "verifier-clean (committed, CI)";
    let data: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&data)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", data.display()));
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", data.display()));

    let bar: &serde_json::Value = parsed["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .filter_map(|group: &serde_json::Value| group["bars"].as_array())
        .flatten()
        .find(|candidate: &&serde_json::Value| candidate["label"].as_str() == Some(BAR))
        .unwrap_or_else(|| {
            panic!(
                "xtask/data/recovery.json must carry a `{BAR}` bar for this gate to be its source"
            )
        });

    let num: u64 = bar["num"].as_u64().expect("the bar records a numerator");
    let den: u64 = bar["den"].as_u64().expect("the bar records a denominator");
    let value: f64 = bar["value"].as_f64().expect("the bar records a percentage");
    let detail: &str = bar["detail"].as_str().expect("the bar records a detail");

    assert_eq!(
        usize::try_from(num).expect("numerator fits usize"),
        VERIFY_CLEAN_CLASS_FLOOR,
        "recovery.json publishes {num} verifier-clean classes and every document renders that \
         number, but this gate enforces {VERIFY_CLEAN_CLASS_FLOOR}; the published figure is wrong \
         until this assertion passes"
    );
    assert_eq!(
        num, den,
        "the plotted figure is the presentable ratio, so a denominator of {den} against {num} \
         clean classes means the bar no longer plots what its label says"
    );
    assert!(
        (value - 100.0).abs() < f64::EPSILON,
        "recovery.json plots {value}% for {num} of {den} classes; the percentage and the counts \
         beside it have drifted apart"
    );
    let bodies: String = format!("{BODY_VERIFY_CLEAN_FLOOR} re-hosted method bodies verify clean");
    assert!(
        detail.contains(&bodies),
        "the `{BAR}` detail does not state `{bodies}`, but this gate enforces \
         {BODY_VERIFY_CLEAN_FLOOR} re-hosted bodies; the prose that ships beside the chart states a \
         body count nothing measures"
    );
}
