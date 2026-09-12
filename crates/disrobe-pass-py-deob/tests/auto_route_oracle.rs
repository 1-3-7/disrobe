#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::{AutoDeobOutcome, RouteKind, auto_deobfuscate, supported_obfuscators};

const RECOVERABLE: &[(&str, &str)] = &[
    ("blankobf", "edge_hello_world"),
    ("blankobf", "edge_recursive"),
    ("plusobf", "edge_hello_world"),
];

#[test]
fn real_obfuscated_fixture_auto_deobfuscates_to_recognizable_source() {
    let mut proved: usize = 0;
    for (obf, slot) in RECOVERABLE {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(obf, slot) else {
            continue;
        };
        let outcome: AutoDeobOutcome = auto_deobfuscate(&fixture, None);
        assert_eq!(
            outcome.kind,
            RouteKind::Deobfuscated,
            "{obf}/{slot} should auto-route to deobfuscation, got {:?}; chain={:?}",
            outcome.kind,
            outcome.chain
        );
        let source: String = outcome.source.expect("deobfuscated source present");
        assert!(
            !source.trim().is_empty(),
            "{obf}/{slot} recovered empty source"
        );
        assert_ne!(
            source.as_bytes(),
            fixture.as_slice(),
            "{obf}/{slot} output is identical to the obfuscated input"
        );
        let recognizable: bool = source.contains("def ")
            || source.contains("print")
            || source.contains("return")
            || source.contains('=');
        assert!(
            recognizable,
            "{obf}/{slot} recovered source is not recognizable Python:\n{source}"
        );
        assert!(
            outcome.chain.iter().any(|c| c.starts_with("detected")),
            "{obf}/{slot} chain must record the detected family: {:?}",
            outcome.chain
        );
        assert!(
            outcome.chain.iter().any(|c| c.contains("deobfuscated")),
            "{obf}/{slot} chain must record the deobfuscation step: {:?}",
            outcome.chain
        );
        proved += 1;
    }
    assert!(
        proved > 0,
        "no recoverable obfuscated fixture was present; expected at least one of {RECOVERABLE:?}"
    );
}

#[test]
fn unknown_sample_yields_guidance_listing_supported_obfuscators() {
    let unknown: &[u8] =
        b"\x00\x01\x02\x03\xff\xfe garbage that is neither pyc nor known obfuscator \x80\x81";
    let outcome: AutoDeobOutcome = auto_deobfuscate(unknown, None);
    assert_eq!(
        outcome.kind,
        RouteKind::Unidentified,
        "garbage must not be claimed as recovered; got {:?}",
        outcome.kind
    );
    assert!(
        outcome.source.is_none(),
        "unidentified input must not fabricate source"
    );
    let guidance: String = outcome
        .guidance
        .expect("guidance present for unknown input");
    for entry in supported_obfuscators() {
        assert!(
            guidance.contains(entry.display_name),
            "guidance must list supported obfuscator {}: {guidance}",
            entry.display_name
        );
    }
    assert!(
        guidance.contains("disrobe py deob"),
        "guidance must show the exact command to run: {guidance}"
    );
    assert!(
        guidance.contains("--list"),
        "guidance must mention the --list flag: {guidance}"
    );
}

#[test]
fn clean_python_source_is_not_misreported_as_obfuscated() {
    let clean: &[u8] = b"def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n";
    let outcome: AutoDeobOutcome = auto_deobfuscate(clean, None);
    assert_ne!(
        outcome.kind,
        RouteKind::Deobfuscated,
        "clean source has nothing to deobfuscate"
    );
    if outcome.kind == RouteKind::Unidentified {
        let guidance: String = outcome.guidance.expect("guidance");
        assert!(
            guidance.contains("could not identify"),
            "clean-source guidance should be the non-obfuscated variant: {guidance}"
        );
    }
}
