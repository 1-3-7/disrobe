#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_jvm::{AndroidAuditReport, AuditFinding, audit_android_apk};

const REFLECTION: &str = "DR-APK-REFLECTION";

fn fixture(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit");
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn audit(rel: &str) -> AndroidAuditReport {
    let bytes: Vec<u8> = fixture(rel);
    audit_android_apk(&bytes).expect("audit the fixture")
}

fn rule_counts(report: &AndroidAuditReport) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for finding in &report.findings {
        let finding: &AuditFinding = finding;
        *counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }
    counts
}

fn assert_same_rules(variant: &str, extra: &[&str]) {
    let plain: AndroidAuditReport = audit("audit-plants.apk");
    let obfuscated: AndroidAuditReport = audit(&format!("obfuscapk/{variant}.apk"));
    let mut expected: BTreeMap<String, usize> = rule_counts(&plain);
    for rule in extra {
        *expected.entry((*rule).to_owned()).or_insert(0) += 1;
    }
    assert!(
        !obfuscated.truncated && obfuscated.methods_scanned >= plain.methods_scanned,
        "{variant}: scanned {} methods against {} in the plain build",
        obfuscated.methods_scanned,
        plain.methods_scanned
    );
    let actual: BTreeMap<String, usize> = rule_counts(&obfuscated);
    let differences: Vec<String> = expected
        .keys()
        .chain(actual.keys())
        .collect::<std::collections::BTreeSet<&String>>()
        .into_iter()
        .filter(|rule: &&String| expected.get(*rule) != actual.get(*rule))
        .map(|rule: &String| {
            format!(
                "{rule}: plain {} obfuscated {}",
                expected.get(rule).copied().unwrap_or(0),
                actual.get(rule).copied().unwrap_or(0)
            )
        })
        .collect();
    assert!(
        differences.is_empty(),
        "{variant}: every rule that fires on the plain build fires as often on the obfuscated build: {differences:?}"
    );
}

#[test]
fn goto_chains_do_not_hide_the_method_shapes() {
    assert_same_rules("goto", &[]);
}

#[test]
fn reordered_blocks_keep_every_constant_to_call_binding() {
    assert_same_rules("reorder", &[]);
}

#[test]
fn call_indirection_wrappers_resolve_to_the_api_they_forward_to() {
    let plain: AndroidAuditReport = audit("audit-plants.apk");
    let wrapped: AndroidAuditReport = audit("obfuscapk/callind.apk");
    assert!(
        wrapped.methods_scanned > plain.methods_scanned,
        "the fixture carries the forwarding wrappers: {} methods against {}",
        wrapped.methods_scanned,
        plain.methods_scanned
    );
    assert_same_rules("callind", &[]);
}

#[test]
fn advanced_reflection_tables_resolve_to_the_hidden_api() {
    assert_same_rules("advreflection", &[REFLECTION]);
}
