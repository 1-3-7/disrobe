#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::PathBuf;

use disrobe_core::recon::{
    ReconCategory, ReconConfig, ReconFinding, ReconReport, report_bytes, report_tree,
    scan_zip_bytes,
};

fn planted_apk() -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/recon/apk/planted-secrets.apk");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read planted apk {}: {e}", path.display()))
}

fn rule_ids(report: &ReconReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.rule_id.clone())
        .collect()
}

fn rule_ids_from(findings: &[ReconFinding]) -> BTreeSet<String> {
    findings
        .iter()
        .map(|f: &ReconFinding| f.rule_id.clone())
        .collect()
}

#[test]
fn real_apk_surfaces_every_planted_apkleaks_secret() {
    let apk: Vec<u8> = planted_apk();
    let report: ReconReport =
        report_bytes(&apk, Some("planted-secrets.apk"), &ReconConfig::default());
    let ids: BTreeSet<String> = rule_ids(&report);
    for required in [
        "DR-SEC-AWS-AKID",
        "DR-SEC-AWS-SECRET",
        "DR-RECON-FIREBASE",
        "DR-SEC-GCP-APIKEY",
        "DR-RECON-S3-BUCKET",
        "DR-SEC-BASIC-AUTH",
        "DR-SEC-JWT",
        "DR-RECON-AUTH-BEARER",
        "DR-RECON-GOOGLE-OAUTH-TOKEN",
    ] {
        assert!(
            ids.contains(required),
            "real apk missing apkleaks-class rule {required}: {ids:?}"
        );
    }
}

#[test]
fn apk_findings_attribute_inner_entry_paths() {
    let apk: Vec<u8> = planted_apk();
    let findings: Vec<ReconFinding> =
        scan_zip_bytes(&apk, Some("planted-secrets.apk"), &ReconConfig::default());
    let aws: &ReconFinding = findings
        .iter()
        .find(|f: &&ReconFinding| f.rule_id == "DR-SEC-AWS-AKID")
        .expect("aws key in apk");
    assert_eq!(
        aws.path.as_deref(),
        Some("planted-secrets.apk!res/raw/credentials.properties"),
        "aws finding must name its inner archive entry: {aws:?}"
    );
    assert!(
        aws.value.contains('\u{2026}'),
        "secret preview must be redacted: {aws:?}"
    );
}

#[test]
fn apk_manifest_recon_inside_archive() {
    let apk: Vec<u8> = planted_apk();
    let report: ReconReport =
        report_bytes(&apk, Some("planted-secrets.apk"), &ReconConfig::default());
    let ids: BTreeSet<String> = rule_ids(&report);
    assert!(
        ids.contains("DR-RECON-MANIFEST-EXPORTED"),
        "manifest recon inside apk: {ids:?}"
    );
    let cats: BTreeSet<ReconCategory> = report
        .findings
        .iter()
        .map(|f: &ReconFinding| f.category)
        .collect();
    assert!(cats.contains(&ReconCategory::Manifest), "{cats:?}");
}

#[test]
fn report_tree_unpacks_apk_in_directory() {
    let apk: Vec<u8> = planted_apk();
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-apk-tree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("app.apk"), &apk).expect("write apk");
    let report: ReconReport = report_tree(&dir, &ReconConfig::default()).expect("scan tree");
    let _ = std::fs::remove_dir_all(&dir);
    let ids: BTreeSet<String> = rule_ids(&report);
    assert!(ids.contains("DR-SEC-AWS-AKID"), "tree apk unpack: {ids:?}");
    assert!(
        ids.contains("DR-RECON-FIREBASE"),
        "tree apk unpack: {ids:?}"
    );
}

#[test]
fn clean_apk_yields_no_secrets() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor: std::io::Cursor<&mut Vec<u8>> = std::io::Cursor::new(&mut buf);
        let mut zip: zip::ZipWriter<std::io::Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("res/values/strings.xml", opts).unwrap();
        zip.write_all(b"<resources><string name=\"app_name\">Clean App</string></resources>")
            .unwrap();
        zip.start_file("assets/readme.txt", opts).unwrap();
        zip.write_all(b"the quick brown fox jumps over thirteen lazy dogs nightly")
            .unwrap();
        zip.finish().unwrap();
    }
    let findings: Vec<ReconFinding> =
        scan_zip_bytes(&buf, Some("clean.apk"), &ReconConfig::default());
    let ids: BTreeSet<String> = rule_ids_from(&findings);
    for forbidden in [
        "DR-SEC-AWS-AKID",
        "DR-SEC-AWS-SECRET",
        "DR-RECON-FIREBASE",
        "DR-SEC-GCP-APIKEY",
        "DR-SEC-BASIC-AUTH",
        "DR-SEC-JWT",
    ] {
        assert!(
            !ids.contains(forbidden),
            "clean apk false-positived {forbidden}: {ids:?}"
        );
    }
}
