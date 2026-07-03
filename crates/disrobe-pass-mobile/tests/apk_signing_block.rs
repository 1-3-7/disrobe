#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_mobile::apk_recon::analyze;
use disrobe_pass_mobile::apk_signing::{
    APK_SIGNATURE_SCHEME_V2_BLOCK_ID, APK_SIGNATURE_SCHEME_V3_BLOCK_ID, ApkSigningBlockReport,
    SchemeBlock, SignatureScheme, SignerCertificate, VERITY_PADDING_BLOCK_ID,
    parse as parse_signing,
};

const ORACLE_CERT_SHA256: &str = "f8b7664fada9b0f39d7a972abb28c137095c6532091e98df4f113b31bf23d49c";
const ORACLE_SUBJECT: &str = "CN=Disrobe Fixture,O=disrobe,C=US";
const ORACLE_SERIAL_HEX: &str = "05560d9a91bc1468";

fn read_fixture(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

#[test]
fn v2v3_signing_block_signer_cert_matches_keytool_oracle() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v2v3-signed.apk");
    let report: ApkSigningBlockReport = parse_signing(&apk);

    assert!(
        report.signing_block_present,
        "APK Signing Block must be located in the v2v3 fixture"
    );
    assert!(
        report.has_scheme(SignatureScheme::V2),
        "v2 block (0x7109871a) must be parsed: ids={:?}",
        report.block_ids
    );
    assert!(
        report.has_scheme(SignatureScheme::V3),
        "v3 block (0xf05368c0) must be parsed: ids={:?}",
        report.block_ids
    );
    assert!(
        report.block_ids.contains(&APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
            && report.block_ids.contains(&APK_SIGNATURE_SCHEME_V3_BLOCK_ID),
        "both v2 and v3 ids enumerated: {:?}",
        report.block_ids
    );
    assert!(
        report.verity_padding_present && report.block_ids.contains(&VERITY_PADDING_BLOCK_ID),
        "verity padding block (0x42726577) present in the apksigner-built fixture"
    );

    for scheme in [SignatureScheme::V2, SignatureScheme::V3] {
        let block: &SchemeBlock = report.scheme(scheme).expect("scheme present");
        assert_eq!(
            block.signers.len(),
            1,
            "exactly one signer in the {} block",
            scheme.label()
        );
        let cert: &SignerCertificate = block.signers[0]
            .certificates
            .first()
            .expect("signer carries a certificate");
        assert_eq!(
            cert.sha256_fingerprint,
            ORACLE_CERT_SHA256,
            "{} signer cert SHA-256 must match keytool/openssl oracle",
            scheme.label()
        );
        assert_eq!(
            cert.subject,
            ORACLE_SUBJECT,
            "{} signer cert subject must match keytool oracle",
            scheme.label()
        );
        assert_eq!(
            cert.issuer,
            ORACLE_SUBJECT,
            "{} signer cert issuer (self-signed) must match keytool oracle",
            scheme.label()
        );
        assert_eq!(
            cert.serial_hex,
            ORACLE_SERIAL_HEX,
            "{} signer cert serial must match keytool oracle",
            scheme.label()
        );
    }
}

#[test]
fn apk_recon_surfaces_signing_block_fingerprints() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v2v3-signed.apk");
    let report = analyze(&apk).expect("analyze v2v3 apk");
    assert!(
        report.signing.signing_block_present,
        "apk recon must surface the signing block"
    );
    let fps: Vec<&str> = report.signing.signer_fingerprints();
    assert!(
        fps.iter().all(|f: &&str| *f == ORACLE_CERT_SHA256),
        "every surfaced signer fingerprint matches the oracle: {fps:?}"
    );
    assert!(
        !fps.is_empty(),
        "at least one signer fingerprint surfaced through recon"
    );
}

#[test]
fn tampered_apk_still_recovers_signer_identity() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-tampered.apk");
    let report: ApkSigningBlockReport = parse_signing(&apk);
    assert!(
        report.signing_block_present,
        "byte-flipped apk still carries the signing block structurally"
    );
    let cert: &SignerCertificate = report
        .scheme(SignatureScheme::V2)
        .expect("v2 still present")
        .signers
        .first()
        .expect("signer present")
        .certificates
        .first()
        .expect("cert present");
    assert_eq!(
        cert.sha256_fingerprint, ORACLE_CERT_SHA256,
        "the signer cert is intact in the tampered fixture (only zip content was flipped)"
    );
}

#[test]
fn v1_only_apk_has_no_signing_block() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-v1-signed.apk");
    let report: ApkSigningBlockReport = parse_signing(&apk);
    assert!(
        !report.signing_block_present,
        "v1-only fixture (JAR signing) carries no APK Signing Block"
    );
    assert!(report.schemes.is_empty(), "no v2/v3 schemes present");
}

#[test]
fn non_apk_input_yields_empty_signing_report() {
    let report: ApkSigningBlockReport = parse_signing(b"not a zip at all, just text");
    assert!(!report.signing_block_present);
    assert!(report.schemes.is_empty());
    assert_eq!(report.block_size, 0);
}
