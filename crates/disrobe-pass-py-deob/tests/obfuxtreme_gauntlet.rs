#![allow(clippy::expect_used, clippy::panic)]

use std::io::Read;

use base64::Engine;
use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::ObfuXtremePass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const WRAPPED: &[u8] = include_bytes!(
    "../../../corpus/python/obfuscators/obfuxtreme/gauntlet/real_v4_artifact.py.fixture"
);

fn unwrap_fixture(wrapped: &[u8]) -> Vec<u8> {
    let magic: &[u8] = b"DISROBE_OBFUSCATOR_FIXTURE_ZLIB_BASE64_V1";
    let after: &[u8] = wrapped.strip_prefix(magic).expect("fixture magic");
    let rest: &[u8] = after
        .strip_prefix(b"\n")
        .or_else(|| after.strip_prefix(b"\r\n"))
        .unwrap_or(after);
    let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let b64_decoded: Vec<u8> = engine.decode(rest.trim_ascii()).expect("base64");
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
        flate2::read::ZlibDecoder::new(b64_decoded.as_slice());
    let mut out: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut out).expect("zlib");
    out
}

#[test]
fn obfuxtreme_real_v4_artifact_recovers_runnable_source() {
    let artifact: Vec<u8> = unwrap_fixture(WRAPPED);
    let det: DetectReport = ObfuXtremePass.detect(&artifact);
    assert!(
        det.matched,
        "real ObfuXtreme v4 loader must be detected: {det:?}"
    );

    let peel: PeelOutcome = ObfuXtremePass
        .peel(&artifact)
        .expect("peel must succeed on the real ObfuXtreme v4 artifact");
    assert_eq!(
        peel.quality,
        Quality::Full,
        "AES key/iv recover + AES-256-CBC decrypt + zlib + marshal + decompile + per-string AES decrypt must fully reverse the v4 loader; got {:?} ({:?})",
        peel.quality,
        peel.lossy_notes
    );

    for stage in [
        "xor-key-recover",
        "xor-iv-recover",
        "aes-256-cbc-decrypt",
        "marshal-load",
        "decompile",
        "string-aes-decrypt",
    ] {
        assert!(
            peel.stages_applied.iter().any(|s: &String| s == stage),
            "expected stage {stage:?}, got {:?}",
            peel.stages_applied
        );
    }

    let src: &str = &peel.recovered_source;
    assert!(
        !src.contains("_decrypt_str(b") && !src.contains("_decrypt_bytes(b"),
        "every AES-wrapped string constant must be statically decrypted; got: {src}"
    );

    for needle in [
        "import math",
        "def greet(",
        "def compute(",
        "class Calculator:",
        "def main(",
        "'Hello, '",
        "'world'",
        "'__main__'",
        "math.sqrt(144)",
    ] {
        assert!(
            src.contains(needle),
            "recovered source must contain {needle:?}; recovered:\n{src}"
        );
    }
}
