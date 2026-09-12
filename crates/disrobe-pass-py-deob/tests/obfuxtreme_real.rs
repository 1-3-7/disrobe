#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::obfuxtreme::ObfuXtremePass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[(&str, &str)] = &[
    ("edge_cases_3_8", ""),
    ("edge_hello_world", "hello world"),
    ("edge_recursive", "def fact"),
    ("edge_class_decorator", "class Box"),
    ("edge_async_fn", "async def fetch"),
    ("edge_generator", "yield"),
    ("edge_lambda_in_listcomp", "lambda"),
    ("edge_typing_generic", "Generic"),
    ("edge_walrus_operator", ":="),
];

#[test]
fn obfuxtreme_real_v4_fixtures_recover_source() {
    let mut tested: usize = 0;
    for (slot, needle) in SLOTS {
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
            Quality::Full,
            "obfuxtreme slot {slot}: AES decrypt + zlib + marshal-load + decompile + string-decrypt must fully recover source, got {:?} (lossy={:?})",
            peel.quality,
            peel.lossy_notes
        );
        for stage in [
            "aes-256-cbc-decrypt",
            "zlib-decompress",
            "marshal-load",
            "decompile",
        ] {
            assert!(
                peel.stages_applied.iter().any(|s: &String| s == stage),
                "obfuxtreme slot {slot}: expected stage {stage:?}, got {:?}",
                peel.stages_applied
            );
        }
        assert!(
            peel.diagnostics
                .get("recovered_parses")
                .is_some_and(|v: &String| v == "true"),
            "obfuxtreme slot {slot}: recovered source must re-parse as Python; diagnostics={:?}",
            peel.diagnostics
        );
        assert!(
            !peel.recovered_source.contains("_decrypt_str(b")
                && !peel.recovered_source.contains("_decrypt_bytes(b"),
            "obfuxtreme slot {slot}: every AES-wrapped string constant must be statically decrypted; got first 300 bytes: {:?}",
            &peel.recovered_source.chars().take(300).collect::<String>()
        );
        assert!(
            peel.recovered_source.contains(needle),
            "obfuxtreme slot {slot}: recovered source missing {needle:?}; got first 300 bytes: {:?}",
            &peel.recovered_source.chars().take(300).collect::<String>()
        );
    }
    if tested == 0 {
        common::skip_absent_corpus("obfuxtreme_real_v4_fixtures_recover_source", "obfuxtreme");
        return;
    }
    assert!(
        tested >= 8,
        "expected 8+ obfuxtreme real fixtures, got {tested}"
    );
}

#[test]
fn obfuxtreme_real_strings_decrypt_to_literals() {
    let Some(fixture): Option<Vec<u8>> =
        common::load_real_fixture("obfuxtreme", "edge_hello_world")
    else {
        common::skip_absent_corpus("obfuxtreme_real_strings_decrypt_to_literals", "obfuxtreme");
        return;
    };
    let peel: PeelOutcome = ObfuXtremePass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("obfuxtreme hello_world peel: {e:?}"));
    assert_eq!(peel.quality, Quality::Full);
    assert!(
        peel.diagnostics
            .get("strings_decrypted")
            .and_then(|v: &String| v.parse::<usize>().ok())
            .is_some_and(|n: usize| n >= 1),
        "obfuxtreme hello_world: at least one AES string constant must be statically decrypted; diagnostics={:?}",
        peel.diagnostics
    );
    assert!(
        peel.recovered_source.contains("'hello world'"),
        "obfuxtreme hello_world: decrypted string literal must appear in source; got: {:?}",
        peel.recovered_source
    );
}
