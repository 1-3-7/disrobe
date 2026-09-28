#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::{Path, PathBuf};

use disrobe_pass_py_deob::obfuscators::patchwork::PatchworkPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};
use disrobe_pass_py_deob::{ObfuscatorPass, RouteKind, auto_deobfuscate};

const ARTIFACT_NEEDLES: &[&str] = &[
    "b85decode",
    "__import__('marshal')",
    "__import__('zlib')",
    "id(int)",
    "_pw_",
    "addaudithook",
    "gettrace",
    "__pw_ab",
    "__pw_ab_dispatch__",
];

fn assert_clean(source: &str, slot: &str) {
    for needle in ARTIFACT_NEEDLES {
        assert!(
            !source.contains(needle),
            "patchwork artifact `{needle}` survived in recovered source for {slot}:\n{source}"
        );
    }
    assert!(
        ruff_parses(source),
        "recovered source for {slot} does not parse:\n{source}"
    );
}

fn ruff_parses(source: &str) -> bool {
    use ruff_python_parser::{Mode, ParseOptions, parse};
    parse(source, ParseOptions::from(Mode::Module)).is_ok()
}

fn peel_slot(slot: &str) -> PeelOutcome {
    let fixture: Vec<u8> = common::require_real_fixture("patchwork", slot);
    let detect: DetectReport = PatchworkPass.detect(&fixture);
    assert!(
        detect.matched,
        "patchwork slot {slot} not detected: {detect:?}"
    );
    assert!(
        detect.confidence >= 0.8,
        "patchwork slot {slot} low confidence: {detect:?}"
    );
    let outcome: PeelOutcome = PatchworkPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("patchwork slot {slot} peel failed: {e:?}"));
    assert_eq!(
        outcome.quality,
        Quality::Full,
        "patchwork slot {slot} did not reach full recovery"
    );
    outcome
}

#[test]
fn patchwork_hello_world_py_recovers_to_equivalent_source() {
    let outcome: PeelOutcome = peel_slot("hello_world");
    let src: &str = &outcome.recovered_source;
    assert_clean(src, "hello_world");
    assert!(
        src.contains("'Hello, World!'"),
        "missing greeting literal:\n{src}"
    );
    assert!(src.contains("' from '"), "missing concat literal:\n{src}");
    assert!(src.contains("'patchwork'"), "missing call argument:\n{src}");
    assert!(
        src.contains("'number:'") && src.contains("42"),
        "missing number print:\n{src}"
    );
    assert!(
        src.contains("a + b") || src.contains("(a + b)"),
        "missing add body:\n{src}"
    );
    assert!(
        src.contains("__name__ == '__main__'"),
        "missing main guard:\n{src}"
    );
}

#[test]
fn patchwork_pyc_chain_recovers() {
    let bytes: Vec<u8> = read_tracked_fixture("real_hello_world.pyc");
    let detect: DetectReport = PatchworkPass.detect(&bytes);
    assert!(detect.matched, "patchwork .pyc not detected: {detect:?}");
    assert!(
        detect
            .markers
            .iter()
            .any(|m: &String| m.contains("pyc-loader")),
        "expected pyc-loader marker: {detect:?}"
    );
    let outcome: PeelOutcome = PatchworkPass.peel(&bytes).expect("pyc peel");
    assert_eq!(outcome.quality, Quality::Full);
    assert_clean(&outcome.recovered_source, "hello_world.pyc");
    assert!(
        outcome.recovered_source.contains("'Hello, World!'"),
        "pyc recovery lost greeting:\n{}",
        outcome.recovered_source
    );
}

fn read_tracked_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_root().join("patchwork").join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "the tracked patchwork fixture {} is unreadable ({e}); restore it with git checkout",
            path.display()
        )
    })
}

#[test]
fn patchwork_norename_preserves_original_identifiers() {
    let outcome: PeelOutcome = peel_slot("hello_world_norename");
    let src: &str = &outcome.recovered_source;
    assert_clean(src, "hello_world_norename");
    assert!(
        src.contains("GREETING"),
        "original GREETING name lost:\n{src}"
    );
    assert!(
        src.contains("def greet(") && src.contains("def add("),
        "original function names lost:\n{src}"
    );
    assert!(
        src.contains("'Hello, World!'"),
        "greeting literal lost:\n{src}"
    );
}

#[test]
fn patchwork_features_module_recovers_structure() {
    let outcome: PeelOutcome = peel_slot("features");
    let src: &str = &outcome.recovered_source;
    assert_clean(src, "features");
    assert!(src.contains("import math"), "lost import:\n{src}");
    assert!(
        src.contains("'alpha'") && src.contains("'gamma'"),
        "lost list literals:\n{src}"
    );
    assert!(
        src.contains("'big'") && src.contains("'medium'") && src.contains("'small'"),
        "lost branch literals:\n{src}"
    );
    assert!(src.contains("class "), "lost class def:\n{src}");
    assert!(src.contains(".floor(3.7)"), "lost attribute call:\n{src}");
    assert!(
        src.contains("n > 100") && src.contains("n > 10"),
        "lost branch conditions:\n{src}"
    );
}

#[test]
fn patchwork_auto_route_recognizes_samples() {
    let fixture: Vec<u8> = common::require_real_fixture("patchwork", "hello_world");
    let route = auto_deobfuscate(&fixture, None);
    assert_eq!(
        route.kind,
        RouteKind::Deobfuscated,
        "auto route did not deobfuscate"
    );
    let chain: String = route.chain.join(" | ");
    assert!(
        chain.contains("Patchwork"),
        "auto route chain missing Patchwork: {chain}"
    );
}

#[test]
fn patchwork_recovered_source_is_behaviorally_equivalent() {
    let python: PathBuf = common::require_python();
    let cases: &[(&str, &str)] = &[
        ("hello_world", "orig_hello.py"),
        ("hello_world_norename", "orig_hello.py"),
        ("features", "orig_features.py"),
    ];
    for (slot, original) in cases {
        let outcome: PeelOutcome = peel_slot(slot);
        let expected: String = expected_stdout(&python, original);
        let actual: Option<String> = run_python_source(&python, &outcome.recovered_source);
        assert_eq!(
            actual.as_deref(),
            Some(expected.as_str()),
            "recovered source for {slot} does not reproduce original stdout"
        );
    }
}

fn read_original(name: &str) -> String {
    String::from_utf8(read_tracked_fixture(name))
        .unwrap_or_else(|e| panic!("the tracked patchwork original {name} is not UTF-8: {e}"))
}

fn expected_stdout(python: &Path, original: &str) -> String {
    run_python_source(python, &read_original(original)).unwrap_or_else(|| {
        panic!(
            "the repository-authored original {original} must run cleanly under {}",
            python.display()
        )
    })
}

fn run_python_source(python: &Path, source: &str) -> Option<String> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_pw_oracle").ok()?;
    let dir: std::path::PathBuf = scratch.path().to_path_buf();
    let file: std::path::PathBuf = dir.join("candidate.py");
    std::fs::write(&file, source).ok()?;
    let output: std::process::Output = std::process::Command::new(python)
        .arg(&file)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[test]
fn patchwork_rejects_clean_and_garbage_inputs() {
    let clean: &[u8] = b"def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n";
    assert!(
        !PatchworkPass.detect(clean).matched,
        "clean source misdetected"
    );

    let dropper: &[u8] = b"import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n";
    assert!(
        !PatchworkPass.detect(dropper).matched,
        "generic dropper misdetected"
    );

    let garbage: &[u8] = &[
        0x00u8, 0x01, 0x02, 0x99, 0xfe, 0xed, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    assert!(
        !PatchworkPass.detect(garbage).matched,
        "garbage misdetected as patchwork"
    );
    assert!(
        PatchworkPass.peel(garbage).is_err(),
        "garbage must not peel"
    );
}

const ABYSS_CASES: &[(&str, &str)] = &[
    ("arith_abyss", "orig_arith.py"),
    ("compare_abyss", "orig_compare.py"),
    ("loops_abyss", "orig_loops.py"),
    ("comp_abyss", "orig_comp.py"),
    ("fstr_abyss", "orig_fstr.py"),
    ("walrus_abyss", "orig_walrus.py"),
];

#[test]
fn patchwork_abyss_devirtualizes_every_opcode_family() {
    let python: PathBuf = common::require_python();
    for (slot, original) in ABYSS_CASES {
        let outcome: PeelOutcome = peel_slot(slot);
        let src: &str = &outcome.recovered_source;
        assert_clean(src, slot);
        assert!(
            outcome
                .stages_applied
                .iter()
                .any(|s: &String| s.starts_with("abyss-devirt")),
            "{slot} did not record an abyss-devirt stage: {:?}",
            outcome.stages_applied
        );
        assert_eq!(
            outcome
                .diagnostics
                .get("abyss_functions_refused")
                .map(String::as_str),
            Some("0"),
            "{slot} refused an abyss body it should have lifted"
        );
        let expected: String = expected_stdout(&python, original);
        let actual: Option<String> = run_python_source(&python, src);
        assert_eq!(
            actual.as_deref(),
            Some(expected.as_str()),
            "abyss-devirt {slot} does not reproduce original stdout\nrecovered:\n{src}"
        );
    }
}

#[test]
fn patchwork_abyss_auto_chain_recovers_pyc_bodies() {
    let bytes: Vec<u8> = read_tracked_fixture("real_arith_abyss.pyc");
    let route = auto_deobfuscate(&bytes, None);
    assert_eq!(
        route.kind,
        RouteKind::Deobfuscated,
        "abyss .pyc auto route did not deobfuscate"
    );
    let chain: String = route.chain.join(" | ");
    assert!(
        chain.contains("Patchwork"),
        "abyss auto chain missing Patchwork: {chain}"
    );
    let recovered: &str = route.source.as_deref().unwrap_or_default();
    for needle in ARTIFACT_NEEDLES {
        assert!(
            !recovered.contains(needle),
            "abyss auto-chain left artifact `{needle}`:\n{recovered}"
        );
    }
    assert!(
        recovered.contains("x = a + b * 2 - 1"),
        "abyss auto-chain lost the protected function body:\n{recovered}"
    );

    let python: PathBuf = common::require_python();
    let expected: String = expected_stdout(&python, "orig_arith.py");
    let actual: Option<String> = run_python_source(&python, recovered);
    assert_eq!(
        actual.as_deref(),
        Some(expected.as_str()),
        "abyss auto-chain recovery not behaviorally equivalent"
    );
}
