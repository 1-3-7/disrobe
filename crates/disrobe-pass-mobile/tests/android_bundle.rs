#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Write as _};
use std::path::PathBuf;

use disrobe_core::Rung;
use disrobe_core::chain::{ChildArtifact, DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::{Artifact, LegacyPass};
use disrobe_pass_mobile::chain_detector::{MOBILE_PASS, MobileDetector};
use disrobe_pass_mobile::pass::{
    BundleFormat, DetectedKind, MobilePass, MobilePassOutput, detect_bundle_format, detect_kind,
};
use zip::write::SimpleFileOptions;

fn hello_dex() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/dex/Hello.dex");
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        zw.start_file::<&str, ()>(name, opts).expect("start entry");
        zw.write_all(data).expect("write entry");
    }
    zw.finish().expect("finish zip").into_inner()
}

fn build_base_apk(dex: &[u8]) -> Vec<u8> {
    zip_of(&[
        ("classes.dex", dex),
        (
            "AndroidManifest.xml",
            b"<manifest package=\"com.disrobe.hello\"/>",
        ),
    ])
}

fn build_xapk(dex: &[u8]) -> Vec<u8> {
    let base: Vec<u8> = build_base_apk(dex);
    let split: Vec<u8> = zip_of(&[("resources.arsc", b"\x02\x00\x0c\x00")]);
    zip_of(&[
        ("base.apk", &base),
        ("split_config.arm64_v8a.apk", &split),
        (
            "info.json",
            b"{\"xapk_version\":2,\"package_name\":\"com.disrobe.hello\"}",
        ),
        ("icon.png", b"\x89PNG\r\n\x1a\n"),
    ])
}

fn build_apkm(dex: &[u8]) -> Vec<u8> {
    let base: Vec<u8> = build_base_apk(dex);
    let split: Vec<u8> = zip_of(&[("resources.arsc", b"\x02\x00\x0c\x00")]);
    zip_of(&[("base.apk", &base), ("split_config.xxhdpi.apk", &split)])
}

fn build_aab(dex: &[u8]) -> Vec<u8> {
    zip_of(&[
        ("BundleConfig.pb", b"\x08\x01"),
        ("base/manifest/AndroidManifest.xml", b"\x0a\x07android"),
        ("base/dex/classes.dex", dex),
        ("base/resources.pb", b"\x12\x00"),
    ])
}

const fn ctx(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

#[test]
fn xapk_and_apkm_classify_as_android_bundle() {
    let dex: Vec<u8> = hello_dex();
    let xapk: Vec<u8> = build_xapk(&dex);
    let apkm: Vec<u8> = build_apkm(&dex);

    assert_eq!(detect_kind(&xapk), DetectedKind::AndroidBundle);
    assert_eq!(detect_kind(&apkm), DetectedKind::AndroidBundle);
    assert_eq!(detect_bundle_format(&xapk), Some(BundleFormat::Xapk));
    assert_eq!(detect_bundle_format(&apkm), Some(BundleFormat::Apkm));
}

#[test]
fn aab_classifies_as_android_bundle() {
    let dex: Vec<u8> = hello_dex();
    let aab: Vec<u8> = build_aab(&dex);
    assert_eq!(detect_kind(&aab), DetectedKind::AndroidBundle);
    assert_eq!(detect_bundle_format(&aab), Some(BundleFormat::Aab));
}

#[test]
fn bundle_verdict_outranks_generic_zip_and_marks_format() {
    let dex: Vec<u8> = hello_dex();
    let xapk: Vec<u8> = build_xapk(&dex);
    let verdict: DetectVerdict = MobileDetector
        .detect(&ctx(&xapk))
        .expect("xapk must be detected");
    assert_eq!(verdict.format_tag, "android-bundle");
    assert!(
        verdict.confidence >= 0.93,
        "android-bundle must outrank the generic zip/react-native fallback (0.80); got {}",
        verdict.confidence
    );
    assert!(
        verdict.markers.contains(&"xapk"),
        "verdict must carry the bundle-format marker; markers={:?}",
        verdict.markers
    );
}

#[test]
fn xapk_extract_children_yields_inner_apks_routed_to_android() {
    let dex: Vec<u8> = hello_dex();
    let xapk: Vec<u8> = build_xapk(&dex);
    let artifact: Artifact = Artifact::new(Rung::Raw, xapk, [0u8; 32]);
    let children: Vec<ChildArtifact> = MOBILE_PASS
        .extract_children(&artifact)
        .expect("bundle children extract");

    let base: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "base.apk")
        .expect("base.apk must be extracted as a child");
    assert_eq!(
        base.handle.hint.as_deref(),
        Some("android-apk"),
        "the inner base.apk must be re-fed as an android-apk so the chain routes it to android, not native"
    );
    assert!(
        children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path == "split_config.arm64_v8a.apk"),
        "split config apks must also be extracted for cross-split analysis"
    );

    let recovered_dex: bool = base.bytes.windows(8).any(|w: &[u8]| w == b"dex\n035\0");
    assert!(
        recovered_dex,
        "the extracted base.apk must still contain the real classes.dex"
    );
}

#[test]
fn aab_extract_children_yields_dex_routed_to_jvm() {
    let dex: Vec<u8> = hello_dex();
    let aab: Vec<u8> = build_aab(&dex);
    let artifact: Artifact = Artifact::new(Rung::Raw, aab, [0u8; 32]);
    let children: Vec<ChildArtifact> = MOBILE_PASS
        .extract_children(&artifact)
        .expect("aab children extract");

    let dex_child: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "base/dex/classes.dex")
        .expect("base/dex/classes.dex must be extracted from the aab");
    assert_eq!(
        dex_child.handle.hint.as_deref(),
        Some("android-dex"),
        "aab dex must be routed straight to jvm as android-dex"
    );
    assert_eq!(dex_child.bytes, dex, "extracted dex must be byte-exact");
}

#[test]
fn bundle_pass_run_reports_format_and_dex() {
    let dex: Vec<u8> = hello_dex();
    let xapk: Vec<u8> = build_xapk(&dex);
    let raw: Artifact = Artifact::new(Rung::Raw, xapk, [0u8; 32]);
    let out: Artifact = LegacyPass::run(&MobilePass, &raw).expect("mobile pass runs on xapk");
    let report: MobilePassOutput =
        serde_json::from_slice(out.envelope.as_slice()).expect("decode mobile output");
    assert_eq!(report.detected, DetectedKind::AndroidBundle);
    let bundle = report
        .android_bundle
        .expect("android_bundle report present");
    assert_eq!(bundle.format, BundleFormat::Xapk);
    assert!(
        bundle.apks.iter().any(|e| e.name == "base.apk"),
        "report must list the inner base.apk"
    );
}

#[test]
fn plain_apk_still_classifies_as_apk_not_bundle() {
    let dex: Vec<u8> = hello_dex();
    let apk: Vec<u8> = build_base_apk(&dex);
    assert_eq!(
        detect_kind(&apk),
        DetectedKind::AndroidDexApk,
        "a normal single apk must not be misread as a bundle"
    );
    assert_eq!(detect_bundle_format(&apk), None);
}
