#![allow(clippy::expect_used, clippy::panic)]

use std::io::Read;

use base64::Engine;
use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const WRAPPED: &[u8] = include_bytes!(
    "../../../corpus/python/obfuscators/kramer/gauntlet/real_pyc_artifact.py.fixture"
);

const CLEAN_APP: &str =
    include_str!("../../../corpus/python/obfuscators/kramer/gauntlet/clean_app.py");

fn unwrap_fixture(wrapped: &[u8]) -> Vec<u8> {
    let magic: &[u8] = b"DISROBE_OBFUSCATOR_FIXTURE_ZLIB_BASE64_V1";
    let rest: &[u8] = wrapped
        .strip_prefix(magic)
        .expect("fixture magic")
        .strip_prefix(b"\n")
        .or_else(|| {
            wrapped
                .strip_prefix(magic)
                .and_then(|r| r.strip_prefix(b"\r\n"))
        })
        .expect("fixture newline");
    let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let b64_decoded: Vec<u8> = engine.decode(rest.trim_ascii()).expect("base64");
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
        flate2::read::ZlibDecoder::new(b64_decoded.as_slice());
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).expect("zlib");
    out
}

#[test]
fn kramer_real_compiled_pyc_artifact_recovers_app_byte_exact() {
    let pyc: Vec<u8> = unwrap_fixture(WRAPPED);
    assert!(pyc.len() > 16, "compiled artifact must be non-trivial");
    assert_eq!(&pyc[2..4], &[0x0d, 0x0a], "must be a real .pyc header");

    let det: DetectReport = KramerPass.detect(&pyc);
    assert!(
        det.matched,
        "real Kramer compiled .pyc artifact must be detected: {det:?}"
    );

    let peel: PeelOutcome = KramerPass
        .peel(&pyc)
        .expect("peel must succeed on the real compiled .pyc artifact");
    assert_eq!(
        peel.quality,
        Quality::Full,
        "the actual distributed Kramer artifact is a compiled .pyc; its hex _sparkle blob must fully recover, got {:?} ({:?})",
        peel.quality,
        peel.lossy_notes
    );
    assert!(
        peel.stages_applied
            .iter()
            .any(|s: &String| s == "pyc-blob-scan"),
        "recovery must run through the compiled-pyc blob-scan path, got {:?}",
        peel.stages_applied
    );
    assert_eq!(
        peel.recovered_source, CLEAN_APP,
        "Kramer's Kyrie+key+hex transform is lossless; the compiled .pyc must recover the original app byte-for-byte"
    );
}
