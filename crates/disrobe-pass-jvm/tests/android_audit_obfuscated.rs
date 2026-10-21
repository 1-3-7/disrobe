#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_jvm::{
    AndroidAuditReport, AuditFinding, CallSiteOutcome, CallSiteRecovery, GenericStringRecovery,
    audit_android_apk, extract_apk, parse_dex, recover_dex_strings_generic,
};

const REFLECTION: (&str, &str) = (
    "DR-APK-REFLECTION",
    "Lcom/apireflectionmanager/AdvancedApiReflection;",
);
const API_REFLECTION: (&str, &str) = (
    "DR-APK-REFLECTION",
    "Lcom/apireflectionmanager/ApiReflection;",
);
const DECRYPTOR: &str = "Lcom/decryptstringmanager/DecryptString;";
const DECRYPTOR_ECB: (&str, &str) = ("DR-APK-CRYPTO-ECB", DECRYPTOR);
const DECRYPTOR_KEY: (&str, &str) = ("DR-APK-CRYPTO-HARDCODED-KEY", DECRYPTOR);

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

fn assert_same_rules(variant: &str, extra: &[(&str, &str)]) {
    let plain: AndroidAuditReport = audit("audit-plants.apk");
    let obfuscated: AndroidAuditReport = audit(&format!("obfuscapk/{variant}.apk"));
    let mut expected: BTreeMap<String, usize> = rule_counts(&plain);
    for (rule, class) in extra {
        *expected.entry((*rule).to_owned()).or_insert(0) += 1;
        assert!(
            obfuscated
                .findings
                .iter()
                .any(|f: &AuditFinding| f.rule_id == *rule && f.class == *class),
            "{variant}: the obfuscator's own helper {class} is reported under {rule}"
        );
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

#[test]
fn encrypted_constants_are_recovered_before_the_string_rules_run() {
    assert_same_rules("strings", &[DECRYPTOR_ECB, DECRYPTOR_KEY]);
}

#[test]
fn the_full_transform_chain_loses_no_rule() {
    assert_same_rules(
        "full",
        &[REFLECTION, API_REFLECTION, DECRYPTOR_ECB, DECRYPTOR_KEY],
    );
}

fn string_recovery(rel: &str) -> GenericStringRecovery {
    let bytes: Vec<u8> = fixture(rel);
    let extract = extract_apk(&bytes).expect("apk container");
    let dex_bytes: &Vec<u8> = extract.dex_files.values().next().expect("classes.dex");
    let dex = parse_dex(dex_bytes).expect("parse classes.dex");
    recover_dex_strings_generic(&dex, dex_bytes)
}

fn assert_every_site_recovered(rel: &str, minimum: usize) {
    let recovery: GenericStringRecovery = string_recovery(rel);
    let skipped: Vec<String> = recovery
        .call_sites
        .iter()
        .filter(|site: &&CallSiteRecovery| !matches!(site.outcome, CallSiteOutcome::Recovered(_)))
        .map(|site: &CallSiteRecovery| {
            format!(
                "{}->{} pc {} via {}->{}: {:?}",
                site.caller_class,
                site.caller_method,
                site.pc,
                site.decrypt_class,
                site.decrypt_method,
                site.outcome
            )
        })
        .collect();
    assert!(
        skipped.is_empty() && recovery.recovered_count() >= minimum,
        "{rel}: {} candidates, {} of {} call sites recovered (at least {minimum} expected); skipped: {skipped:?}",
        recovery.candidates_found,
        recovery.recovered_count(),
        recovery.call_sites.len()
    );
}

#[test]
fn every_encrypted_constant_call_site_is_recovered_through_the_decryptor() {
    assert_every_site_recovered("obfuscapk/strings.apk", 28);
}

#[test]
fn every_encrypted_constant_call_site_is_recovered_through_forwarding_wrappers() {
    assert_every_site_recovered("obfuscapk/full.apk", 28);
}
