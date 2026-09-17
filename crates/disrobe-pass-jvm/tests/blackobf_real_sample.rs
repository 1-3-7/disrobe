#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

pub mod common;

use std::path::PathBuf;

use common::{
    JvmVerifier, VerifyScope, assert_permille, find_on_path, lines_with_prefix, parse_metric,
};
use disrobe_pass_jvm::assemble_jar;
use disrobe_pass_jvm::dalvik::SwitchPayload;
use disrobe_pass_jvm::dalvik_blackobf::{
    BlackObfDeflatten, BlackObfReport, deflatten_blackobfuscator, detect_blackobfuscator,
};
use disrobe_pass_jvm::dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg_from_code_item};
use disrobe_pass_jvm::dex::{CodeItemsReport, DexFile, parse, parse_code_items};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};

const REAL_HELLO_D2: &[u8] = include_bytes!("fixtures/blackobfuscator/Hello.d2.dex");
const REAL_EDGECASES_D1: &[u8] = include_bytes!("fixtures/blackobfuscator/EdgeCases.d1.dex");

const CLEAN_ORIGINALS: &[(&str, &[u8])] = &[
    (
        "Hello.dex",
        include_bytes!("../../../corpus/jvm/dex/Hello.dex"),
    ),
    (
        "EdgeCases.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex"),
    ),
    (
        "EdgeCasesKt.dex",
        include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex"),
    ),
];

const HELLO_FLAGGED_FLOOR: usize = 4;
const HELLO_CASE_FLOOR: usize = 46;
const EDGECASES_FLAGGED_FLOOR: usize = 175;
const EDGECASES_CASE_FLOOR: usize = 2312;
const WHOLE_BODY_POPULATION_PERMILLE: u32 = 1000;
const VERIFY_CLEAN_CLASS_FLOOR: usize = 65;
const BODY_CLEAN_FLOOR: usize = 167;
const BODY_FAIL_CEILING: usize = 0;
const LIFTER_FAIL_CEILING: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seed {
    Intact,
    OneKeyPerDispatcherBroken,
}

const BROKEN_KEY: i32 = i32::MIN;

#[derive(Debug, Default, PartialEq, Eq)]
struct Census {
    methods: usize,
    flagged: usize,
    dispatchers: usize,
    dispatch_cases: usize,
    resolved_cases: usize,
    unresolved_cases: usize,
    masked_methods: usize,
    linear_blocks: usize,
}

fn seeded_payloads(built: &DalvikMethodCfg, seed: Seed) -> Vec<(u32, SwitchPayload)> {
    built
        .switch_payloads
        .iter()
        .map(|(pc, payload): &(u32, SwitchPayload)| {
            let mut keys: Vec<i32> = payload.keys.clone();
            if seed == Seed::OneKeyPerDispatcherBroken
                && let Some(slot) = keys.first_mut()
            {
                *slot = BROKEN_KEY;
            }
            (
                *pc,
                SwitchPayload {
                    keys,
                    targets: payload.targets.clone(),
                },
            )
        })
        .collect()
}

fn census(bytes: &[u8], seed: Seed) -> Census {
    let dex: DexFile = parse(bytes).expect("parse the dex under census");
    let report: CodeItemsReport = parse_code_items(&dex, bytes);
    let mut out: Census = Census::default();
    for item in report.decoded() {
        out.methods += 1;
        let Some(built): Option<DalvikMethodCfg> = build_dalvik_cfg_from_code_item(item) else {
            continue;
        };
        let payloads: Vec<(u32, SwitchPayload)> = seeded_payloads(&built, seed);
        let detected: BlackObfReport = detect_blackobfuscator(&built.insns, &payloads);
        if !detected.flattened {
            continue;
        }
        out.flagged += 1;
        out.dispatchers += detected.dispatcher_count;
        out.dispatch_cases += detected.dispatch_cases;
        let Some(deflatten): Option<BlackObfDeflatten> =
            deflatten_blackobfuscator(&built.insns, &payloads, &dex.strings)
        else {
            continue;
        };
        out.resolved_cases += deflatten.resolved_cases;
        out.unresolved_cases += deflatten.unresolved_cases;
        out.linear_blocks += deflatten.linear_block_pcs.len();
        if deflatten.dispatch_mask != 0 {
            out.masked_methods += 1;
        }
    }
    out
}

#[test]
fn real_blackobfuscator_output_is_detected_and_its_dispatch_map_resolves() {
    for (label, bytes) in CLEAN_ORIGINALS {
        let clean: Census = census(bytes, Seed::Intact);
        eprintln!(
            "BLACKOBF CLEAN {label}: methods={} flagged={}",
            clean.methods, clean.flagged
        );
        assert_eq!(
            clean.flagged, 0,
            "{label} is the pre-obfuscation original, so nothing in it may be reported as \
             hashCode-dispatcher flattening"
        );
    }

    let hello: Census = census(REAL_HELLO_D2, Seed::Intact);
    let edge: Census = census(REAL_EDGECASES_D1, Seed::Intact);
    for (label, measured) in [("Hello.d2", &hello), ("EdgeCases.d1", &edge)] {
        let pct: f64 =
            measured.resolved_cases as f64 * 100.0 / measured.dispatch_cases.max(1) as f64;
        eprintln!(
            "BLACKOBF REAL {label}: methods={} flagged={} cases={} resolved={} unresolved={} \
             masked_methods={} linear_blocks={} ({pct:.1}% of dispatcher cases mapped back to a block)",
            measured.methods,
            measured.flagged,
            measured.dispatch_cases,
            measured.resolved_cases,
            measured.unresolved_cases,
            measured.masked_methods,
            measured.linear_blocks
        );
    }

    assert!(
        hello.flagged >= HELLO_FLAGGED_FLOOR,
        "real BlackObfuscator 2.2 output over Hello.dex flattened {HELLO_FLAGGED_FLOOR} methods, \
         but only {} were detected",
        hello.flagged
    );
    assert!(
        hello.resolved_cases >= HELLO_CASE_FLOOR,
        "only {} of {} dispatcher cases in the real Hello sample resolved to a block, floor is \
         {HELLO_CASE_FLOOR}",
        hello.resolved_cases,
        hello.dispatch_cases
    );
    assert!(
        edge.flagged >= EDGECASES_FLAGGED_FLOOR,
        "only {} methods of the real EdgeCases sample were detected, floor is \
         {EDGECASES_FLAGGED_FLOOR}",
        edge.flagged
    );
    assert!(
        edge.resolved_cases >= EDGECASES_CASE_FLOOR,
        "only {} of {} dispatcher cases in the real EdgeCases sample resolved to a block, floor is \
         {EDGECASES_CASE_FLOOR}",
        edge.resolved_cases,
        edge.dispatch_cases
    );
    assert!(
        hello.masked_methods >= HELLO_FLAGGED_FLOOR,
        "every dispatcher this tool emits keys its cases as blockName.hashCode() xor a per-method \
         constant, so all {HELLO_FLAGGED_FLOOR} flattened methods were expected to yield a \
         non-zero mask and only {} did",
        hello.masked_methods
    );
}

#[test]
fn one_broken_key_per_dispatcher_drops_the_census_below_its_floor() {
    let intact: Census = census(REAL_HELLO_D2, Seed::Intact);
    let seeded: Census = census(REAL_HELLO_D2, Seed::OneKeyPerDispatcherBroken);
    eprintln!(
        "BLACKOBF SEEDED DEFECT: intact resolved={} of {} over {} dispatcher(s); one key per \
         dispatcher replaced -> resolved={} unresolved={}",
        intact.resolved_cases,
        intact.dispatch_cases,
        intact.dispatchers,
        seeded.resolved_cases,
        seeded.unresolved_cases
    );
    assert!(
        intact.resolved_cases >= HELLO_CASE_FLOOR,
        "the intact sample must clear the floor for this control to mean anything"
    );
    assert_eq!(
        seeded.resolved_cases + intact.dispatchers,
        intact.resolved_cases,
        "replacing one key per dispatcher must cost exactly one resolved case per dispatcher"
    );
    assert_eq!(
        seeded.unresolved_cases, intact.dispatchers,
        "each broken key must be reported as an unresolved case rather than silently dropped"
    );
    assert!(
        seeded.resolved_cases < HELLO_CASE_FLOOR,
        "a dispatcher key that corresponds to no block name must pull the census below its floor; \
         it still reported {} of {} resolved, so the floor can be met without recovering the \
         dispatch map",
        seeded.resolved_cases,
        seeded.dispatch_cases
    );
}

#[test]
fn recovered_classes_from_a_real_blackobfuscator_dex_pass_the_real_jvm_verifier() {
    assert!(
        find_on_path("java").is_some() && find_on_path("javac").is_some(),
        "a JDK 24+ is required: this gate re-hosts the classes recovered from real BlackObfuscator \
         output and runs them through -Xverify:all, which is the only grading reference here that \
         disrobe does not own. CI provisions one with actions/setup-java, so a missing JDK is a \
         broken environment and not a reason to report a green run"
    );
    let verifier: JvmVerifier = JvmVerifier::prepare(&format!(
        "disrobe_blackobf_real_sample_{}",
        std::process::id()
    ))
    .unwrap_or_else(|why: String| panic!("prepare the jvm verifier helper: {why}"));

    let mut total_clean: usize = 0;
    let mut total_lifter_fail: usize = 0;
    let mut total_body_clean: usize = 0;
    let mut total_body_fail: usize = 0;
    let mut errors: Vec<String> = Vec::new();

    for (label, bytes) in [
        ("Hello.d2", REAL_HELLO_D2),
        ("EdgeCases.d1", REAL_EDGECASES_D1),
    ] {
        let result: Dex2JarResult =
            translate_dex_bytes(bytes).expect("translate the real obfuscated dex");
        let jar: Vec<u8> = assemble_jar(&result).expect("assemble the recovered jar");
        let jar_path: PathBuf = verifier.write_jar(label, &jar);
        let stdout: String = verifier.run(
            VerifyScope::Classes {
                permille: WHOLE_BODY_POPULATION_PERMILLE,
            },
            jar_path.as_path(),
        );
        assert_permille(&stdout, WHOLE_BODY_POPULATION_PERMILLE);
        let clean: usize = parse_metric(&stdout, "verify_clean_classes=");
        let lifter_fail: usize = parse_metric(&stdout, "lifter_verify_fail_classes=");
        let body_clean: usize = parse_metric(&stdout, "body_clean=");
        let body_fail: usize = parse_metric(&stdout, "body_fail=");
        eprintln!(
            "BLACKOBF VERIFY {label}: recovered_classes={} clean={clean} lifter_fail={lifter_fail} \
             link_skipped={} body_clean={body_clean} body_fail={body_fail}",
            result.classes.len(),
            parse_metric(&stdout, "link_skipped_classes=")
        );
        assert_eq!(
            body_fail,
            0,
            "{label} still has a verifier-rejected recovered method body:\n{}",
            lines_with_prefix(&stdout, "BODYVERIFY ").join("\n")
        );
        assert_eq!(
            lifter_fail,
            0,
            "{label} still has a verifier-rejected recovered class:\n{}",
            lines_with_prefix(&stdout, "VERIFY ").join("\n")
        );
        total_clean += clean;
        total_lifter_fail += lifter_fail;
        total_body_clean += body_clean;
        total_body_fail += body_fail;
        errors.extend(lines_with_prefix(&stdout, "VERIFY "));
        errors.extend(lines_with_prefix(&stdout, "BODYVERIFY "));
    }

    eprintln!(
        "BLACKOBF VERIFY TOTAL: clean_classes={total_clean} lifter_fail_classes={total_lifter_fail} \
         body_clean={total_body_clean} body_fail={total_body_fail}"
    );
    for line in &errors {
        eprintln!("  {line}");
    }

    assert!(
        total_clean >= VERIFY_CLEAN_CLASS_FLOOR,
        "only {total_clean} classes recovered from real BlackObfuscator output pass -Xverify:all, \
         floor is {VERIFY_CLEAN_CLASS_FLOOR}"
    );
    assert!(
        total_body_clean >= BODY_CLEAN_FLOOR,
        "only {total_body_clean} recovered method bodies pass the per-method -Xverify:all carrier, \
         floor is {BODY_CLEAN_FLOOR}"
    );
    assert_eq!(
        total_body_fail,
        BODY_FAIL_CEILING,
        "the JVM rejected {total_body_fail} re-hosted method bodies recovered from real \
         BlackObfuscator output:\n{}",
        errors.join("\n")
    );
    assert!(
        total_lifter_fail <= LIFTER_FAIL_CEILING,
        "{total_lifter_fail} whole classes recovered from real BlackObfuscator output are rejected \
         by the JVM verifier, above the measured residual of {LIFTER_FAIL_CEILING}:\n{}",
        errors.join("\n")
    );
}
