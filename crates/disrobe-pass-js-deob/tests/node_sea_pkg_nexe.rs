#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::v8::nexe::{NEXE_FOOTER_MAGIC, NexeLocation, detect_nexe_suffix};
use disrobe_pass_js_deob::v8::pkg::{PkgLocation, detect_pkg_payload};
use disrobe_pass_js_deob::v8::sea::{
    SEA_MAGIC, SeaBlob, SeaBlobLocation, carve_sea_main_code, detect_node_sea_blob, parse_sea_blob,
};

fn synth_real_sea(code_path: &str, main_code: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&SEA_MAGIC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&(code_path.len() as u64).to_le_bytes());
    out.extend_from_slice(code_path.as_bytes());
    out.extend_from_slice(&(main_code.len() as u64).to_le_bytes());
    out.extend_from_slice(main_code);
    out
}

fn corpus_sea_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p: &Path| p.to_path_buf())
        .unwrap_or(manifest)
        .join("corpus/js")
        .join(rel)
}

#[test]
fn synthetic_real_format_sea_blob_detected_and_parsed() {
    let bytes: Vec<u8> = synth_real_sea("script.js", b"console.log('sea-bundle');\n");
    let loc: SeaBlobLocation = detect_node_sea_blob(&bytes).expect("sea detected");
    assert_eq!(loc.blob_offset, 0u64);
    let blob: SeaBlob = parse_sea_blob(&bytes).expect("parse");
    assert_eq!(blob.magic, SEA_MAGIC);
    assert_eq!(blob.code_path, "script.js");
    assert_eq!(blob.main_code_len, 27u64);
    let main: Vec<u8> = carve_sea_main_code(&bytes, &blob).expect("carve");
    assert_eq!(main, b"console.log('sea-bundle');\n");
}

#[test]
fn vercel_pkg_payload_offset_recovered_from_suffix() {
    const MARKER: &[u8] = b"PAYLOAD_POSITION";
    let mut bytes: Vec<u8> = vec![0u8; 1024];
    bytes[100..100 + MARKER.len()].copy_from_slice(MARKER);
    let payload_off: u64 = 512u64;
    let payload_size: u64 = 32u64;
    bytes.extend_from_slice(&payload_size.to_le_bytes());
    bytes.extend_from_slice(&payload_off.to_le_bytes());
    let loc: PkgLocation = detect_pkg_payload(&bytes).expect("pkg location");
    assert_eq!(loc.payload_size, payload_size);
    assert_eq!(loc.payload_offset, payload_off);
}

#[test]
fn nexe_footer_sizes_recovered_from_suffix() {
    let mut bytes: Vec<u8> = vec![0u8; 256];
    let code_len: u64 = 100u64;
    let resource_len: u64 = 50u64;
    let total: usize = usize::try_from(code_len + resource_len).unwrap();
    bytes.extend(std::iter::repeat_n(0u8, total));
    bytes.extend_from_slice(&code_len.to_le_bytes());
    bytes.extend_from_slice(&resource_len.to_le_bytes());
    bytes.extend_from_slice(NEXE_FOOTER_MAGIC);
    let loc: NexeLocation = detect_nexe_suffix(&bytes).expect("nexe");
    assert_eq!(loc.payload_size, code_len + resource_len);
}

#[test]
fn real_node_sea_prep_blob_parses_with_correct_magic_and_code_path() {
    let path: PathBuf = corpus_sea_path("sea/sea-prep.blob");
    let bytes: Vec<u8> = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => panic!(
            "missing real SEA fixture at {}: {e}; regenerate with \
             `node --experimental-sea-config sea-config.json`",
            path.display()
        ),
    };
    assert!(
        bytes.len() >= 10,
        "real sea-prep.blob must have at least 10 header bytes; got {}",
        bytes.len()
    );
    assert_eq!(
        &bytes[..4],
        &SEA_MAGIC.to_le_bytes(),
        "real sea-prep.blob does not start with SEA_MAGIC 0x{SEA_MAGIC:08X} \
         - fixture corrupt or regeneration needed"
    );
    let blob: SeaBlob = parse_sea_blob(&bytes).expect("parse real sea-prep.blob");
    assert_eq!(blob.magic, SEA_MAGIC);
    assert_eq!(blob.magic_offset, 0u64);
    assert!(
        !blob.code_path.is_empty(),
        "real sea-prep.blob must record a non-empty code path"
    );
    assert!(
        std::path::Path::new(&blob.code_path)
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("js")),
        "real sea-prep.blob code path should be a .js file, got {:?}",
        blob.code_path
    );
    assert!(
        blob.main_code_len > 0u64,
        "real sea-prep.blob must contain non-empty main code"
    );
    let main: Vec<u8> = carve_sea_main_code(&bytes, &blob).expect("carve main code");
    let main_str: &str = std::str::from_utf8(&main).expect("main code is utf-8");
    assert!(
        main_str.contains("console.log") || main_str.contains("require") || !main_str.is_empty(),
        "real sea-prep.blob main code looks empty/garbage: {main_str:?}"
    );
}
