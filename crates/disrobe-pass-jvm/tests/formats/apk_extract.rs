#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::{ApkExtract, extract_apk};

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("apk");
    p.push(name);
    p
}

#[test]
fn extracts_apk_with_manifest_and_dex() {
    let bytes: Vec<u8> = fs::read(corpus("fixture-v2v3-signed.apk")).expect("read apk fixture");
    let apk: ApkExtract = extract_apk(&bytes).expect("extract apk");
    assert!(
        apk.dex_files.contains_key("classes.dex"),
        "real signed apk must contain classes.dex, found: {:?}",
        apk.dex_files.keys().collect::<Vec<_>>()
    );
    assert!(
        apk.manifest_bytes.is_some(),
        "real apk must contain a binary AndroidManifest.xml"
    );
    let manifest: &[u8] = apk.manifest_bytes.as_deref().expect("manifest bytes");
    assert!(
        manifest.starts_with(&[0x03, 0x00, 0x08, 0x00]) || manifest.starts_with(&[0x02, 0x00]),
        "AndroidManifest.xml must be binary AXML (chunk magic), got {:02x?}",
        &manifest[..manifest.len().min(4)]
    );
    assert!(
        apk.resources_arsc.is_some(),
        "aapt2-linked apk must contain resources.arsc"
    );
    let dex: &Vec<u8> = apk.dex_files.get("classes.dex").expect("classes.dex");
    assert_eq!(&dex[..4], b"dex\n", "classes.dex must carry the dex magic");
}

#[test]
fn extracts_v1_signature_files() {
    let bytes: Vec<u8> = fs::read(corpus("fixture-v1-signed.apk")).expect("read v1 apk");
    let apk: ApkExtract = extract_apk(&bytes).expect("extract apk");
    assert!(
        apk.signatures
            .keys()
            .any(|k: &String| k.ends_with(".RSA") || k.ends_with(".SF")),
        "v1-signed apk must expose META-INF signature files, found: {:?}",
        apk.signatures.keys().collect::<Vec<_>>()
    );
}
