#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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

const CONTROL_INLINE_FLOORS: [(&str, usize); 17] = [
    ("booleans", 15),
    ("compact", 16),
    ("controlFlowFlattening", 32),
    ("deadCodeInjection", 21),
    ("debugProtection", 20),
    ("identifiersHexadecimal", 17),
    ("identifiersMangled", 14),
    ("numbersToExpressions", 10),
    ("objectTransform", 14),
    ("renameProperties", 14),
    ("selfDefending", 15),
    ("splitStrings", 19),
    ("stringArrayBase64", 18),
    ("stringArrayRc4", 18),
    ("stringArrayRotate", 18),
    ("stringArrayShuffle", 18),
    ("unicodeEscape", 13),
];

fn read_if_present(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn control_fixture_stems_on_disk() -> Vec<String> {
    let dir: PathBuf = controls_dir();
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

#[test]
fn recovers_string_array_across_control_fixtures() {
    let on_disk: Vec<String> = control_fixture_stems_on_disk();
    let mut declared: Vec<String> = CONTROL_INLINE_FLOORS
        .iter()
        .map(|(stem, _): &(&str, usize)| (*stem).to_owned())
        .collect();
    declared.sort();
    assert_eq!(
        on_disk, declared,
        "every control fixture on disk must be graded here; a new fixture needs a row in CONTROL_INLINE_FLOORS"
    );

    let mut graded: usize = 0;
    for (stem, inline_floor) in CONTROL_INLINE_FLOORS {
        let path: PathBuf = controls_dir().join(format!("{stem}.js"));
        let src: String = read_if_present(&path)
            .unwrap_or_else(|| panic!("control fixture {} is required", path.display()));
        let rec: StringArrayRecovery = recover_string_array(&src)
            .expect("recover ok")
            .unwrap_or_else(|| panic!("{stem}: a string-array recovery is required"));
        assert!(
            rec.call_sites_inlined >= inline_floor,
            "{stem}: inlined string-array call sites must not fall below {inline_floor}; got {}",
            rec.call_sites_inlined
        );
        assert!(
            rec.decoder_name.is_some(),
            "{stem}: the string-array decoder must be identified"
        );
        assert!(
            rec.rewritten_source.len() < src.len(),
            "{stem}: recovery must shrink source; got {} from {}",
            rec.rewritten_source.len(),
            src.len()
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        CONTROL_INLINE_FLOORS.len(),
        "every declared control must be graded; graded {graded}"
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
