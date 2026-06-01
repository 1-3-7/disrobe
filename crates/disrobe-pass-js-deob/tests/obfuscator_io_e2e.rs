#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    ObfuscatorIoOutput, ObfuscatorIoPreset, obfuscator_io_deobfuscate_preset, obfuscator_io_detect,
};

fn fixture_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("src")
        .join("javascript")
        .join("obfuscator-io-samples")
}

fn load_preset_fixture(name: &str) -> Option<String> {
    let path: PathBuf = fixture_root().join("presets").join(format!("{name}.js"));
    read_if_present(&path)
}

fn read_if_present(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn assert_calculator_strings_recovered(
    label: &str,
    source: &str,
    min_call_sites: usize,
    inlined: usize,
) {
    assert!(
        inlined >= min_call_sites,
        "{label}: expected at least {min_call_sites} call sites inlined, got {inlined}"
    );
    let expected: &[&str] = &["divide by ", "zero", "calculator", "ready", "console"];
    for needle in expected {
        assert!(
            source.contains(needle),
            "{label}: rewritten source must contain {needle:?}; head=\n{}",
            &source[..source.len().min(2000)]
        );
    }
}

#[test]
fn e2e_low_preset_recovers_real_string_array() {
    let Some(src) = load_preset_fixture("low") else {
        return;
    };
    let det = obfuscator_io_detect(&src);
    assert!(
        det.matched || !det.controls.is_empty(),
        "detection must fire on real low-preset output"
    );
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(&src, ObfuscatorIoPreset::Low).expect("ok");
    assert!(
        out.string_array_call_sites_inlined > 0,
        "low preset must inline string-array call sites; got {}",
        out.string_array_call_sites_inlined
    );
    assert_calculator_strings_recovered(
        "low",
        &out.source,
        20,
        out.string_array_call_sites_inlined,
    );
}

#[test]
fn e2e_medium_preset_recovers_real_string_array() {
    let Some(src) = load_preset_fixture("medium") else {
        return;
    };
    let det = obfuscator_io_detect(&src);
    assert!(
        det.matched || !det.controls.is_empty(),
        "detection must fire on real medium-preset output"
    );
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(&src, ObfuscatorIoPreset::Medium).expect("ok");
    assert!(
        out.string_array_call_sites_inlined >= 80,
        "medium preset must inline >=80 call sites; got {}",
        out.string_array_call_sites_inlined
    );
    assert_calculator_strings_recovered(
        "medium",
        &out.source,
        80,
        out.string_array_call_sites_inlined,
    );
}

#[test]
fn e2e_high_preset_recovers_real_string_array() {
    let Some(src) = load_preset_fixture("high") else {
        return;
    };
    let det = obfuscator_io_detect(&src);
    assert!(
        det.matched,
        "detection must fire on real high-preset output"
    );
    let out: ObfuscatorIoOutput =
        obfuscator_io_deobfuscate_preset(&src, ObfuscatorIoPreset::High).expect("ok");
    assert!(
        out.string_array_call_sites_inlined >= 400,
        "high preset must inline >=400 call sites; got {}",
        out.string_array_call_sites_inlined
    );
    assert!(
        out.string_array_rotation_count > 0,
        "high preset must use a non-zero rotation; got {}",
        out.string_array_rotation_count
    );
    assert_calculator_strings_recovered(
        "high",
        &out.source,
        400,
        out.string_array_call_sites_inlined,
    );
}

#[test]
fn e2e_control_fixtures_load_when_present() {
    let dir: PathBuf = fixture_root().join("controls");
    if !dir.exists() {
        return;
    }
    let entries = fs::read_dir(&dir).expect("readdir");
    let mut count: usize = 0;
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path
            .extension()
            .is_some_and(|e: &std::ffi::OsStr| e == "js")
        {
            let src: String = fs::read_to_string(&path).expect("read");
            let _det = obfuscator_io_detect(&src);
            count += 1;
        }
    }
    assert!(
        count > 0,
        "expected at least one control fixture to be present"
    );
}
