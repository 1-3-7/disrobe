#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::io::{Cursor, Write as _};

use disrobe_pass_jvm::{JarExtract, extract_jar};

const JAR_BYTES: &[u8] = include_bytes!("../corpus/two_class.jar");
const OVERSIZE_DECLARED: u32 = 0x2000_0000;

fn oversized_declared_zip() -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(160));
    let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("Huge.class", opts).unwrap();
    zip.write_all(b"\xca\xfe\xba\xbe").unwrap();
    let mut bytes: Vec<u8> = zip.finish().unwrap().into_inner();
    bytes[22..26].copy_from_slice(&OVERSIZE_DECLARED.to_le_bytes());
    let central: usize = bytes
        .windows(4)
        .position(|w: &[u8]| w == b"PK\x01\x02")
        .expect("central directory");
    bytes[central + 24..central + 28].copy_from_slice(&OVERSIZE_DECLARED.to_le_bytes());
    bytes
}

#[test]
fn extracts_synthetic_two_class_jar() {
    let jx: JarExtract = extract_jar(JAR_BYTES).expect("extract jar");
    assert_eq!(jx.classes.len(), 2);
    assert!(jx.classes.contains_key("Hello.class"));
    assert!(jx.classes.contains_key("World.class"));
    let manifest: &str = jx.manifest.as_deref().expect("manifest present");
    assert!(manifest.contains("Manifest-Version: 1.0"));
}

#[test]
fn rejects_truncated_zip() {
    let bytes: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
    let err: disrobe_pass_jvm::Error = extract_jar(&bytes).expect_err("truncated");
    assert!(matches!(err, disrobe_pass_jvm::Error::Zip(_)));
}

#[test]
fn rejects_zip_entry_declared_over_cap() {
    let bytes: Vec<u8> = oversized_declared_zip();
    let err: disrobe_pass_jvm::Error = extract_jar(&bytes).expect_err("oversized entry");
    let msg: String = format!("{err}");
    assert!(msg.contains("entry cap"), "got: {msg}");
}
