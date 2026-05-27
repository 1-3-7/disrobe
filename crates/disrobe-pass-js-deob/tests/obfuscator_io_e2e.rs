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

#[test]
fn e2e_low_preset_reduces_real_obfuscator_io_output() {
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
        !out.source.is_empty(),
        "low preset output must not be empty"
    );
}

#[test]
fn e2e_medium_preset_reduces_real_obfuscator_io_output() {
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
    assert!(out.passes_run >= 1);
    assert!(!out.source.is_empty());
}

#[test]
fn e2e_high_preset_reduces_real_obfuscator_io_output() {
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
        !out.controls_applied.is_empty() || !out.per_control_stats.is_empty(),
        "at least one control should fire on real high output; got {:?}",
        out.controls_applied
    );
    assert!(!out.source.is_empty());
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
