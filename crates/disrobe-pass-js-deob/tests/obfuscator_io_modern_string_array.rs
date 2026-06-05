#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! Regression coverage for the modern obfuscator.io string-array layout, asserting recovery decodes real string literals.

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{StringArrayRecovery, recover_string_array};

fn controls_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus/src/javascript/obfuscator-io-samples/controls")
}

fn presets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus/src/javascript/obfuscator-io-samples/presets")
}

fn read_if_present(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    fs::read_to_string(path).ok()
}

#[test]
fn recovers_string_array_across_control_fixtures() {
    let dir: PathBuf = controls_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    let mut total: usize = 0;
    let mut recovered: usize = 0;
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.extension().is_none_or(|e| e != "js") {
            continue;
        }
        let stem: String = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        if stem == "identifiersMangled" {
            continue;
        }
        let src: String = fs::read_to_string(&path).expect("read fixture");
        total += 1;
        if let Some(rec) = recover_string_array(&src).expect("recover ok")
            && rec.call_sites_inlined > 0
        {
            recovered += 1;
            assert!(
                rec.rewritten_source.len() < src.len(),
                "{stem}: recovery must shrink source"
            );
        }
    }
    if total == 0 {
        return;
    }
    assert_eq!(
        recovered, total,
        "every control fixture with a string array must inline >=1 call site ({recovered}/{total})"
    );
}

#[test]
fn recovers_low_preset_string_array() {
    let Some(src) = read_if_present(&presets_dir().join("low.js")) else {
        return;
    };
    let rec: StringArrayRecovery = recover_string_array(&src)
        .expect("recover ok")
        .expect("low preset must yield a recovery");
    assert!(
        rec.call_sites_inlined >= 10,
        "low preset should inline many sites, got {}",
        rec.call_sites_inlined
    );
    assert!(rec.decoder_name.is_some(), "decoder must be identified");
}

#[test]
fn recovers_decoded_literals_are_readable() {
    let Some(src) = read_if_present(&controls_dir().join("stringArrayRotate.js")) else {
        return;
    };
    let rec: StringArrayRecovery = recover_string_array(&src)
        .expect("recover ok")
        .expect("rotate fixture must recover");
    let out: &str = &rec.rewritten_source;
    assert!(
        out.contains("'add'") || out.contains("'sub'") || out.contains("'divide by zero'"),
        "expected decoded calculator literals in output"
    );
    assert!(
        !out.contains("function a0_0x5290("),
        "decoder declaration must be stripped"
    );
}

#[test]
fn modern_recovery_is_deterministic() {
    let Some(src) = read_if_present(&controls_dir().join("stringArrayBase64.js")) else {
        return;
    };
    let first: Option<StringArrayRecovery> = recover_string_array(&src).expect("ok");
    let second: Option<StringArrayRecovery> = recover_string_array(&src).expect("ok");
    match (first, second) {
        (Some(a), Some(b)) => assert_eq!(
            a.rewritten_source, b.rewritten_source,
            "same input must yield identical recovered source"
        ),
        (None, None) => {}
        _ => panic!("recovery determinism violated: one run recovered, the other did not"),
    }
}
