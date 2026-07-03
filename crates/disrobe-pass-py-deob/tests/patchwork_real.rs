#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

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

fn peel_slot(slot: &str) -> Option<(Vec<u8>, PeelOutcome)> {
    let fixture: Vec<u8> = common::load_real_fixture("patchwork", slot)?;
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
    Some((fixture, outcome))
}

#[test]
fn patchwork_hello_world_py_recovers_to_equivalent_source() {
    let Some((_, outcome)): Option<(Vec<u8>, PeelOutcome)> = peel_slot("hello_world") else {
        common::skip_absent_corpus("patchwork_hello_world_py", "patchwork");
        return;
    };
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
    let Some(bytes): Option<Vec<u8>> = read_pyc_fixture() else {
        common::skip_absent_corpus("patchwork_pyc_chain", "patchwork");
        return;
    };
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

fn read_pyc_fixture() -> Option<Vec<u8>> {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: std::path::PathBuf = std::path::PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("obfuscators");
    p.push("patchwork");
    p.push("real_hello_world.pyc");
    std::fs::read(&p).ok()
}

#[test]
fn patchwork_norename_preserves_original_identifiers() {
    let Some((_, outcome)): Option<(Vec<u8>, PeelOutcome)> = peel_slot("hello_world_norename")
    else {
        common::skip_absent_corpus("patchwork_norename", "patchwork");
        return;
    };
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
    let Some((_, outcome)): Option<(Vec<u8>, PeelOutcome)> = peel_slot("features") else {
        common::skip_absent_corpus("patchwork_features", "patchwork");
        return;
    };
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
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("patchwork", "hello_world")
    else {
        common::skip_absent_corpus("patchwork_auto_route", "patchwork");
        return;
    };
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
    let Some(python): Option<String> = find_python() else {
        eprintln!("skip: patchwork behavioral equivalence (no python interpreter on PATH)");
        return;
    };
    let cases: &[(&str, &str)] = &[
        ("hello_world", "orig_hello.py"),
        ("hello_world_norename", "orig_hello.py"),
        ("features", "orig_features.py"),
    ];
    for (slot, original) in cases {
        let Some((_, outcome)): Option<(Vec<u8>, PeelOutcome)> = peel_slot(slot) else {
            continue;
        };
        let Some(expected): Option<String> = run_python_source(&python, &read_original(original))
        else {
            continue;
        };
        let actual: Option<String> = run_python_source(&python, &outcome.recovered_source);
        assert_eq!(
            actual.as_deref(),
            Some(expected.as_str()),
            "recovered source for {slot} does not reproduce original stdout"
        );
    }
}

fn read_original(name: &str) -> String {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: std::path::PathBuf = std::path::PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("obfuscators");
    p.push("patchwork");
    p.push(name);
    std::fs::read_to_string(&p).unwrap_or_default()
}

fn find_python() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        let ok: bool = std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
        if ok {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn run_python_source(python: &str, source: &str) -> Option<String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir: std::path::PathBuf =
        std::env::temp_dir().join(format!("disrobe_pw_oracle_{}_{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let file: std::path::PathBuf = dir.join("candidate.py");
    std::fs::write(&file, source).ok()?;
    let output: std::process::Output = std::process::Command::new(python)
        .arg(&file)
        .output()
        .ok()?;
    let _ = std::fs::remove_dir_all(&dir);
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
    let Some(python): Option<String> = find_python() else {
        eprintln!("skip: patchwork abyss devirt equivalence (no python on PATH)");
        return;
    };
    let mut exercised: usize = 0;
    for (slot, original) in ABYSS_CASES {
        let Some((_, outcome)): Option<(Vec<u8>, PeelOutcome)> = peel_slot(slot) else {
            continue;
        };
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
        let original_src: String = read_original(original);
        let Some(expected): Option<String> = run_python_source(&python, &original_src) else {
            continue;
        };
        let actual: Option<String> = run_python_source(&python, src);
        assert_eq!(
            actual.as_deref(),
            Some(expected.as_str()),
            "abyss-devirt {slot} does not reproduce original stdout\nrecovered:\n{src}"
        );
        exercised += 1;
    }
    assert!(
        exercised >= 1,
        "no abyss corpus slots present; regenerate via patchwork --abyss --seed 424242"
    );
}

#[test]
fn patchwork_abyss_auto_chain_recovers_pyc_bodies() {
    let Some(bytes): Option<Vec<u8>> = read_abyss_pyc_fixture() else {
        common::skip_absent_corpus("patchwork_abyss_pyc_chain", "patchwork");
        return;
    };
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

    if let Some(python) = find_python() {
        let expected: Option<String> = run_python_source(&python, &read_original("orig_arith.py"));
        let actual: Option<String> = run_python_source(&python, recovered);
        if let Some(expected) = expected {
            assert_eq!(
                actual.as_deref(),
                Some(expected.as_str()),
                "abyss auto-chain recovery not behaviorally equivalent"
            );
        }
    }
}

fn read_abyss_pyc_fixture() -> Option<Vec<u8>> {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: std::path::PathBuf = std::path::PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("obfuscators");
    p.push("patchwork");
    p.push("real_arith_abyss.pyc");
    std::fs::read(&p).ok()
}
