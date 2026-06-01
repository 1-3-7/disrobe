#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::ObfuXtremePass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
    "edge_walrus_operator",
];

/// `ObfuXtreme` v4 loaders carry an AES-256-CBC ciphertext whose plaintext is a
/// `zlib(marshal.dumps(code))` blob. We prove the AES key/iv recovery + decrypt + inflate land a
/// marshalled code object (an honest `Quality::Partial`: source needs the py-disasm decompiler);
/// a regression that breaks key/iv extraction would fall to `DetectOnly` and fail this test.
#[test]
fn obfuxtreme_real_v4_fixtures_recover_marshalled_code() {
    let mut tested: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("obfuxtreme", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = ObfuXtremePass.detect(&fixture);
        assert!(det.matched, "obfuxtreme slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = ObfuXtremePass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("obfuxtreme slot {slot} peel: {e:?}"));
        assert_eq!(
            peel.quality,
            Quality::Partial,
            "obfuxtreme slot {slot}: AES decrypt + zlib must reach a marshalled code object (Partial), got {:?} (lossy={:?})",
            peel.quality,
            peel.lossy_notes
        );
        assert!(
            peel.stages_applied
                .iter()
                .any(|s: &String| s == "aes-256-cbc-decrypt")
                && peel
                    .stages_applied
                    .iter()
                    .any(|s: &String| s == "zlib-decompress"),
            "obfuxtreme slot {slot}: expected aes+zlib stages, got {:?}",
            peel.stages_applied
        );
        assert!(
            peel.diagnostics
                .get("marshalled_len")
                .is_some_and(|v: &String| { v.parse::<usize>().is_ok_and(|n: usize| n > 0) }),
            "obfuxtreme slot {slot}: expected non-empty marshalled_len diagnostic, got {:?}",
            peel.diagnostics
        );
    }
    if tested == 0 {
        common::skip_absent_corpus(
            "obfuxtreme_real_v4_fixtures_recover_marshalled_code",
            "obfuxtreme",
        );
        return;
    }
    assert!(
        tested >= 8,
        "expected 8+ obfuxtreme real fixtures, got {tested}"
    );
}
