#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{JarExtract, extract_jar};

const JAR_BYTES: &[u8] = include_bytes!("../corpus/two_class.jar");

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
