#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::apk_sig::{SchemeReport, SignatureScheme, V4Report};
use disrobe_pass_jvm::{ApkSignatureReport, verify_apk_signatures, verify_apk_v4_idsig};

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
    fs::read(corpus(name)).unwrap_or_else(|e: std::io::Error| panic!("read fixture {name}: {e}"))
}

fn len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn build_idsig(apk_digest: &[u8], cert: &[u8]) -> Vec<u8> {
    let mut hashing_info: Vec<u8> = Vec::new();
    hashing_info.extend_from_slice(&1i32.to_le_bytes());
    hashing_info.push(12);
    len_prefixed(&mut hashing_info, &[0u8; 0]);
    len_prefixed(&mut hashing_info, &[0u8; 32]);

    let mut signing_info: Vec<u8> = Vec::new();
    len_prefixed(&mut signing_info, apk_digest);
    len_prefixed(&mut signing_info, cert);
    signing_info.extend_from_slice(&0x0103u32.to_le_bytes());
    len_prefixed(&mut signing_info, &[0xAAu8; 64]);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&2u32.to_le_bytes());
    len_prefixed(&mut out, &hashing_info);
    len_prefixed(&mut out, &signing_info);
    out
}

fn fixture_v3_digest(apk: &[u8]) -> (Vec<u8>, SignatureScheme) {
    let report: ApkSignatureReport = verify_apk_signatures(apk).expect("verify");
    for scheme in [SignatureScheme::V3, SignatureScheme::V2] {
        let Some(sr): Option<&SchemeReport> = report.scheme(scheme) else {
            continue;
        };
        if let Some(d) = sr.digests.first() {
            return (d.computed_digest.clone(), scheme);
        }
    }
    panic!("fixture has neither v2 nor v3 content digest");
}

#[test]
fn v4_idsig_apk_digest_matches_v2_or_v3() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let (digest, scheme): (Vec<u8>, SignatureScheme) = fixture_v3_digest(&apk);

    let idsig: Vec<u8> = build_idsig(&digest, &[]);
    let report: V4Report = verify_apk_v4_idsig(&apk, &idsig).expect("v4 idsig parses");

    assert_eq!(report.version, 2, "V4Signature version field");
    assert_eq!(report.hash_algorithm, 1, "SHA-256 verity hash");
    assert_eq!(report.log2_block_size, 12, "4 KiB verity blocks");
    assert!(
        report.apk_digest_matches_v2_or_v3,
        "the idsig apk_digest equals the apk's real v2/v3 content digest"
    );
    assert_eq!(
        report.matched_scheme,
        Some(scheme),
        "matched the scheme whose computed digest the idsig embeds"
    );
}

#[test]
fn v4_idsig_with_wrong_digest_fails_to_match() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let (mut digest, _): (Vec<u8>, SignatureScheme) = fixture_v3_digest(&apk);
    digest[0] ^= 0xFF;

    let idsig: Vec<u8> = build_idsig(&digest, &[]);
    let report: V4Report = verify_apk_v4_idsig(&apk, &idsig).expect("still parses");
    assert!(
        !report.apk_digest_matches_v2_or_v3,
        "a tampered apk_digest must not match the real content digest"
    );
    assert_eq!(report.matched_scheme, None);
}

#[test]
fn malformed_idsig_is_rejected() {
    let apk: Vec<u8> = read("fixture-v2v3-signed.apk");
    let err = verify_apk_v4_idsig(&apk, &[0u8, 1, 2]).expect_err("truncated idsig");
    assert!(matches!(err, disrobe_pass_jvm::Error::Zip(_)));
}
