#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    ObfuscatorIoDetection, ObfuscatorIoOutput, ObfuscatorIoPreset,
    obfuscator_io_deobfuscate_preset, obfuscator_io_detect,
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

const CONTROL_DETECTION: [(&str, bool, usize); 17] = [
    ("booleans", true, 4),
    ("compact", true, 4),
    ("controlFlowFlattening", true, 4),
    ("deadCodeInjection", true, 4),
    ("debugProtection", true, 5),
    ("identifiersHexadecimal", true, 4),
    ("identifiersMangled", false, 2),
    ("numbersToExpressions", true, 3),
    ("objectTransform", true, 4),
    ("renameProperties", true, 4),
    ("selfDefending", true, 4),
    ("splitStrings", true, 5),
    ("stringArrayBase64", true, 4),
    ("stringArrayRc4", true, 4),
    ("stringArrayRotate", true, 4),
    ("stringArrayShuffle", true, 4),
    ("unicodeEscape", true, 4),
];

fn load_preset_fixture(name: &str) -> Option<String> {
    let path: PathBuf = fixture_root().join("presets").join(format!("{name}.js"));
    read_if_present(&path)
}

fn control_fixture_stems_on_disk() -> Vec<String> {
    let dir: PathBuf = fixture_root().join("controls");
    let entries: fs::ReadDir = fs::read_dir(&dir).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "control fixtures are required under {}: {error}",
            dir.display()
        )
    });
    let mut stems: Vec<String> = entries
        .flatten()
        .map(|entry: fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| {
            path.extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext == "js")
        })
        .filter_map(|path: PathBuf| {
            path.file_stem()
                .and_then(|stem: &std::ffi::OsStr| stem.to_str())
                .map(str::to_owned)
        })
        .collect();
    stems.sort();
    stems
}

fn load_control_fixture(name: &str) -> String {
    let path: PathBuf = fixture_root().join("controls").join(format!("{name}.js"));
    read_if_present(&path)
        .unwrap_or_else(|| panic!("control fixture {} is required", path.display()))
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
fn every_control_fixture_detects_as_obfuscator_io() {
    let on_disk: Vec<String> = control_fixture_stems_on_disk();
    let mut declared: Vec<String> = CONTROL_DETECTION
        .iter()
        .map(|(name, _, _): &(&str, bool, usize)| (*name).to_owned())
        .collect();
    declared.sort();
    assert_eq!(
        on_disk, declared,
        "every control fixture on disk must be graded here; a new fixture needs a row in CONTROL_DETECTION"
    );

    let mut graded: usize = 0;
    for (name, expect_matched, control_floor) in CONTROL_DETECTION {
        let src: String = load_control_fixture(name);
        let det: ObfuscatorIoDetection = obfuscator_io_detect(&src);
        assert_eq!(
            det.matched, expect_matched,
            "{name}: detection must match its declared expectation; if this fires because the detector improved, raise the row rather than the message. markers={:?}",
            det.markers
        );
        assert!(
            det.controls.len() >= control_floor,
            "{name}: detection must report at least {control_floor} controls; got {} as {:?}",
            det.controls.len(),
            det.controls
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        CONTROL_DETECTION.len(),
        "every declared control must be graded; graded {graded}"
    );
}
