#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::io::{Cursor, Write as _};

use disrobe_pass_jvm::{AabExtract, AabModule, Error, extract_aab};

fn build_aab(with_bundle_config: bool) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(512));
    let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    if with_bundle_config {
        zip.start_file("BundleConfig.pb", opts).unwrap();
        zip.write_all(b"\x08\x01").unwrap();
    }
    zip.start_file("base/manifest/AndroidManifest.xml", opts)
        .unwrap();
    zip.write_all(b"\x0a\x07android").unwrap();
    zip.start_file("base/dex/classes.dex", opts).unwrap();
    zip.write_all(b"dex\n035\0padpadpadpad").unwrap();
    zip.start_file("base/dex/classes2.dex", opts).unwrap();
    zip.write_all(b"dex\n035\0padpadpadpad").unwrap();
    zip.start_file("base/resources.pb", opts).unwrap();
    zip.write_all(b"\x12\x00").unwrap();
    zip.start_file("install_time_pack/manifest/AndroidManifest.xml", opts)
        .unwrap();
    zip.write_all(b"\x0a\x04pack").unwrap();
    zip.start_file("META-INF/CERT.RSA", opts).unwrap();
    zip.write_all(b"sig").unwrap();
    zip.start_file("META-INF/CERT.SF", opts).unwrap();
    zip.write_all(b"sf").unwrap();
    zip.finish().unwrap().into_inner()
}

#[test]
fn extracts_aab_modules_manifest_and_dex() {
    let bytes: Vec<u8> = build_aab(true);
    let aab: AabExtract = extract_aab(&bytes).expect("valid aab");
    assert_eq!(
        aab.bundle_config, b"\x08\x01",
        "BundleConfig.pb must be carved byte-exact from the zip entry"
    );
    assert!(aab.modules.contains_key("base"));
    assert!(aab.modules.contains_key("install_time_pack"));
    let base: &AabModule = aab.modules.get("base").expect("base present");
    assert!(base.manifest.is_some());
    assert_eq!(base.dex_files.len(), 2);
    assert!(base.dex_files.contains_key("dex/classes.dex"));
    assert!(base.dex_files.contains_key("dex/classes2.dex"));
    assert!(base.resources_pb.is_some());
    assert_eq!(aab.signatures.len(), 2);
}

#[test]
fn rejects_zip_without_bundle_config() {
    let bytes: Vec<u8> = build_aab(false);
    let err: Error = extract_aab(&bytes).expect_err("not an aab");
    assert!(matches!(err, Error::NotAab));
}

#[test]
fn rejects_non_zip_bytes() {
    let err: Error = extract_aab(&[0x00u8, 0x01, 0x02, 0x03]).expect_err("not a zip");
    assert!(matches!(err, Error::Zip(_)));
}
