#![allow(clippy::expect_used, clippy::panic)]

use std::io::Read;

use base64::Engine;
use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::jawbreaker::JawbreakerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const WRAPPED: &[u8] = include_bytes!(
    "../../../corpus/python/obfuscators/jawbreaker/gauntlet/real_remote_loader.py.fixture"
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
fn jawbreaker_real_remote_loader_peels_to_url_and_honest_wall() {
    let artifact: Vec<u8> = unwrap_fixture(WRAPPED);
    let text: &str = std::str::from_utf8(&artifact).expect("utf-8 artifact");
    assert!(
        !text.contains("def greet") && !text.contains("Calculator") && !text.contains("Hello, "),
        "the remote-loader artifact must not carry the user source statically"
    );

    let det: DetectReport = JawbreakerPass.detect(&artifact);
    assert!(
        det.matched,
        "real Jawbreaker loader must be detected: {det:?}"
    );

    let peel: PeelOutcome = JawbreakerPass
        .peel(&artifact)
        .expect("peel must not error on the real Jawbreaker remote loader");

    assert_eq!(
        peel.quality,
        Quality::DetectOnly,
        "Jawbreaker uploads the user source to a remote paste at build time and leaves only a fetch URL; recovery is an info-theoretic wall (remote payload), so the honest verdict is DetectOnly"
    );
    assert!(
        peel.recovered_source.is_empty(),
        "DetectOnly must not fabricate a recovered source"
    );

    for stage in ["base16", "base32", "base64", "inner-base64"] {
        assert!(
            peel.stages_applied.iter().any(|s: &String| s == stage),
            "both encode layers must be statically peeled to expose the loader; expected {stage:?}, got {:?}",
            peel.stages_applied
        );
    }

    assert_eq!(
        peel.diagnostics.get("remote_loader").map(String::as_str),
        Some("true"),
        "must statically confirm the urllib remote loader; diagnostics={:?}",
        peel.diagnostics
    );
    assert_eq!(
        peel.diagnostics.get("hastebin_url").map(String::as_str),
        Some("https://hastebin.com/raw/oplnldeing"),
        "the exact remote fetch URL must be reconstructed from the char-by-char-joined inner triple-encode; diagnostics={:?}",
        peel.diagnostics
    );
}
