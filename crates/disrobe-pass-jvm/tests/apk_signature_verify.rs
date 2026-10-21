#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::apk_sig::{ApkSignatureReport, SchemeReport, SignatureScheme};
use disrobe_pass_jvm::verify_apk_signatures;

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("apk");
    p.push(name);
    p
}

fn read(name: &str) -> Vec<u8> {
    fs::read(corpus(name)).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {name}: {e}");
    })
}

#[test]
fn v2v3_signed_apk_integrity_verifies() {
    let bytes: Vec<u8> = read("fixture-v2v3-signed.apk");
    let report: ApkSignatureReport = verify_apk_signatures(&bytes).expect("verify");
    assert!(
        report.has_scheme(SignatureScheme::V2),
        "v2 scheme must be present (apksigner oracle: v2=true)"
    );
    assert!(
        report.has_scheme(SignatureScheme::V3),
        "v3 scheme must be present (apksigner oracle: v3=true)"
    );
    let v2: &SchemeReport = report.scheme(SignatureScheme::V2).expect("v2");
    let v3: &SchemeReport = report.scheme(SignatureScheme::V3).expect("v3");
    assert!(
        v2.integrity_verified,
        "v2 content digest must match (apksigner oracle: Verifies)"
    );
    assert!(
        v3.integrity_verified,
        "v3 content digest must match (apksigner oracle: Verifies)"
    );
    assert!(v2.certificate_count >= 1, "v2 must carry a certificate");
    assert!(
        report.overall_integrity_verified,
        "overall integrity must verify (matches apksigner exit 0)"
    );
}

#[test]
fn v1_signed_apk_detected() {
    let bytes: Vec<u8> = read("fixture-v1-signed.apk");
    let report: ApkSignatureReport = verify_apk_signatures(&bytes).expect("verify");
    assert!(
        report.v1_present,
        "v1 JAR signing must be detected (apksigner oracle: v1=true)"
    );
    assert!(
        !report.v1_entries.is_empty(),
        "v1 signature files (.SF/.RSA) must be enumerated"
    );
}

#[test]
fn tampered_apk_integrity_fails() {
    let bytes: Vec<u8> = read("fixture-tampered.apk");
    let report: ApkSignatureReport = verify_apk_signatures(&bytes).expect("parse still ok");
    assert!(
        report.has_scheme(SignatureScheme::V2) || report.has_scheme(SignatureScheme::V3),
        "tampered apk still carries the v2/v3 blocks structurally"
    );
    assert!(
        !report.overall_integrity_verified,
        "tampered apk MUST fail integrity (apksigner oracle: DOES NOT VERIFY, CHUNKED_SHA256 mismatch)"
    );
    let any_mismatch: bool = report
        .schemes
        .iter()
        .flat_map(|s: &SchemeReport| s.digests.iter())
        .any(|d| !d.matches);
    assert!(any_mismatch, "at least one content digest must mismatch");
}

#[test]
fn rejects_non_apk_input() {
    let err = verify_apk_signatures(b"this is not a zip file at all").expect_err("must reject");
    assert!(matches!(err, disrobe_pass_jvm::Error::Zip(_)));
}

#[test]
fn the_audit_fixture_lists_its_one_certificate_once_with_every_scheme() {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/recon/android-audit/audit-plants.apk");
    let bytes: Vec<u8> = fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {}: {e}", path.display());
    });
    let report = disrobe_pass_jvm::analyze_apk_resources(&bytes).expect("apk report");
    assert_eq!(report.certificates.len(), 1, "{:#?}", report.certificates);
    let cert = &report.certificates[0];
    assert_eq!(
        cert.sha256_fingerprint,
        "45:D3:01:80:B9:B8:5A:78:AF:10:D3:14:8A:FD:B1:83:B2:BB:E3:DE:41:F3:77:36:94:00:23:80:F6:5E:BC:A4",
        "apksigner verify --print-certs: 45d30180b9b85a78af10d3148afdb183b2bbe3de41f3773694002380f65ebca4"
    );
    assert_eq!(
        cert.schemes,
        vec![
            "v1 (JAR signing)".to_owned(),
            "v2".to_owned(),
            "v3".to_owned()
        ],
        "apksigner verify: v1, v2 and v3 all true"
    );
    let signatures: ApkSignatureReport = verify_apk_signatures(&bytes).expect("verify");
    assert_eq!(
        signatures.certificates().len(),
        3,
        "the scheme-level report still carries one entry per scheme"
    );
}
