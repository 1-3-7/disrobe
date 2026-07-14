#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use crate::dex::{DexFile, parse as parse_dex};
use crate::dex_builder::{
    CLINIT_KEY_TABLE_DERIVED_KEY, base64_xor_chain_sample, chained_double_decrypt_sample,
    clinit_key_table_sample, dexguard_reflect_sample, native_call_wall_sample,
    stringbuilder_decrypt_sample, xor_bytearray_callsite_sample,
};

fn recovered_strings(report: &GenericStringRecovery) -> Vec<String> {
    report
        .call_sites
        .iter()
        .filter_map(|c: &CallSiteRecovery| match &c.outcome {
            CallSiteOutcome::Recovered(s) => Some(s.clone()),
            CallSiteOutcome::Skipped(_) => None,
        })
        .collect()
}

#[test]
fn recovers_multiple_distinct_byte_array_xor_call_sites_from_a_real_dex() {
    let pairs: [(&str, u8); 3] = [
        ("https://api.example.com/v2/session", 0x37),
        ("X-Correlation-Id", 0x37),
        ("expected-hmac-mismatch", 0x5A),
    ];
    let owned: Vec<(Vec<u8>, u8)> = pairs
        .iter()
        .map(|(plain, key): &(&str, u8)| {
            (
                plain.bytes().map(|b: u8| b ^ key).collect::<Vec<u8>>(),
                *key,
            )
        })
        .collect();
    let call_site_pairs: Vec<(&[u8], u8)> = owned
        .iter()
        .map(|(cipher, key): &(Vec<u8>, u8)| (cipher.as_slice(), *key))
        .collect();
    let dex_bytes: Vec<u8> = xor_bytearray_callsite_sample(&call_site_pairs);
    let dex: DexFile =
        parse_dex(&dex_bytes).expect("the hand-built dex must parse with the real parser");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        report.candidates_found >= 1,
        "the ([BI)String decrypt method must be identified as a candidate"
    );
    let recovered: Vec<String> = recovered_strings(&report);
    for (plain, _) in pairs {
        assert!(
            recovered.iter().any(|s: &String| s == plain),
            "missing {plain:?} in {recovered:?} (call sites: {:?})",
            report.call_sites
        );
    }
    assert_eq!(
        report.recovered_count(),
        pairs.len(),
        "every distinct constant-argument call site must be individually recovered"
    );
}

#[test]
fn flipping_one_ciphertext_byte_changes_the_recovered_output() {
    let plain: &str = "perturbation-check-string";
    let key: u8 = 0x37;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();

    let baseline_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key)]);
    let baseline_dex_file: DexFile = parse_dex(&baseline_dex).expect("parses");
    let baseline: GenericStringRecovery = recover(&baseline_dex_file, &baseline_dex);
    let baseline_recovered: Vec<String> = recovered_strings(&baseline);
    assert!(baseline_recovered.iter().any(|s: &String| s == plain));

    let mut flipped_cipher: Vec<u8> = cipher;
    flipped_cipher[0] ^= 0xFF;
    let flipped_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&flipped_cipher, key)]);
    let flipped_dex_file: DexFile = parse_dex(&flipped_dex).expect("parses");
    let flipped: GenericStringRecovery = recover(&flipped_dex_file, &flipped_dex);
    let flipped_recovered: Vec<String> = recovered_strings(&flipped);

    assert_ne!(
        baseline_recovered, flipped_recovered,
        "a single flipped ciphertext byte must change the recovered output; the test would \
         otherwise be measuring the fixture, not the interpreter"
    );
}

#[test]
fn flipping_the_key_changes_the_recovered_output() {
    let plain: &str = "perturbation-check-string";
    let key: u8 = 0x37;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();

    let baseline_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key)]);
    let baseline_dex_file: DexFile = parse_dex(&baseline_dex).expect("parses");
    let baseline: GenericStringRecovery = recover(&baseline_dex_file, &baseline_dex);
    let baseline_recovered: Vec<String> = recovered_strings(&baseline);
    assert!(baseline_recovered.iter().any(|s: &String| s == plain));

    let flipped_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key ^ 0x01)]);
    let flipped_dex_file: DexFile = parse_dex(&flipped_dex).expect("parses");
    let flipped: GenericStringRecovery = recover(&flipped_dex_file, &flipped_dex);
    let flipped_recovered: Vec<String> = recovered_strings(&flipped);

    assert_ne!(
        baseline_recovered, flipped_recovered,
        "a flipped key must change the recovered output"
    );
}

#[test]
fn recovers_a_clinit_initialized_key_table_by_executing_clinit_under_the_same_budget() {
    let plain: &str = "clinit-derived-key-table";
    let cipher: Vec<u8> = plain
        .bytes()
        .map(|b: u8| b ^ CLINIT_KEY_TABLE_DERIVED_KEY)
        .collect();
    let dex_bytes: Vec<u8> = clinit_key_table_sample(&[&cipher]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "the static KEY field is computed inside <clinit> (0x50 ^ 0x41) and must be executed, \
         not defaulted; missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_stringbuilder_based_decrypt_call_site() {
    let plain: &str = "stringbuilder-decrypt-path";
    let key: u8 = 0x63;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
    let dex_bytes: Vec<u8> = stringbuilder_decrypt_sample(&[(&cipher, key)]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_base64_then_xor_call_site() {
    let plain: &str = "base64-then-xor";
    let key: u8 = 0x2A;
    let dex_bytes: Vec<u8> = base64_xor_chain_sample(&[(plain, key)]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_chained_double_decryption_across_two_call_sites() {
    let plain: &str = "chainedok";
    let k1: u8 = 0x05;
    let k2: u8 = 0x0A;
    let intermediate_bytes: Vec<u8> = plain.bytes().map(|b: u8| b ^ k2).collect();
    let cipher: Vec<u8> = intermediate_bytes.iter().map(|&b: &u8| b ^ k1).collect();
    let dex_bytes: Vec<u8> = chained_double_decrypt_sample(&cipher, k1, k2);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        report.candidates_found >= 2,
        "both stage1([B)String and stage2(String)String must be identified as candidates"
    );
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "the second call site's argument is the runtime result of the first call, not a dex \
         literal; recovering it proves chained-decryption propagation; got {recovered:?} \
         (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn walls_on_a_native_unresolvable_key_dependency_with_a_typed_reason() {
    let cipher: Vec<u8> = b"unreachable-because-native-key".to_vec();
    let dex_bytes: Vec<u8> = native_call_wall_sample(&cipher);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        !report.call_sites.is_empty(),
        "the call site with a constant byte[] argument must still be reported, walled not silently dropped"
    );
    assert!(
        report
            .call_sites
            .iter()
            .all(|c: &CallSiteRecovery| matches!(c.outcome, CallSiteOutcome::Skipped(_))),
        "every call site here depends on an unresolved native key and must be a typed skip, \
         never a fabricated plaintext: {:?}",
        report.call_sites
    );
    assert!(
        report
            .call_sites
            .iter()
            .any(|c: &CallSiteRecovery| matches!(
                &c.outcome,
                CallSiteOutcome::Skipped(SkipReason::UnsupportedCall(m)) if m.contains("nativeKey")
            )),
        "the skip reason must name the unresolved native call: {:?}",
        report.call_sites
    );
}

#[test]
fn walls_on_a_reflection_invoked_decrypt_with_no_direct_constant_call_site() {
    let plaintexts: [&str; 2] = ["reflective-only", "no-direct-call-site"];
    let dex_bytes: Vec<u8> = dexguard_reflect_sample(&plaintexts, 0x66);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.is_empty(),
        "the only call site into decrypt() is via reflection (Method.invoke), which this engine \
         does not model; it must never fabricate a plaintext here: {recovered:?}"
    );
}
