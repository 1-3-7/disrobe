#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{Detection, JsObfuscator, detect, obfuscator_io_detect};

const MAX_FIXTURE_BYTES: u64 = 16 * 1024 * 1024;
const SAMPLE_FIXTURE_FLOOR: usize = 20;
const NEGATIVE_FILE_FLOOR: usize = 132;

const NEGATIVE_FAMILIES: [&str; 23] = [
    "aaencode",
    "babel-preset-env",
    "browserify",
    "bun",
    "closure",
    "esbuild",
    "jjencode",
    "jsconfuser",
    "jscrambler",
    "jsfuck",
    "jsobfu",
    "packer",
    "parcel",
    "protectors",
    "requirejs",
    "rollup",
    "sourcemaps",
    "systemjs",
    "terser",
    "tsc",
    "turbopack",
    "vite",
    "webpack5",
];

const REPORTING_FALSE_POSITIVES: [&str; 2] = [
    "js/aaencode/_encoder-source.js",
    "js/jjencode/_encoder-source.js",
];

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
}

fn relative(path: &Path) -> String {
    path.strip_prefix(corpus())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_bounded(path: &Path) -> Vec<u8> {
    let length: u64 = fs::metadata(path)
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "corpus fixture {} must be readable: {error}",
                path.display()
            )
        })
        .len();
    assert!(
        length <= MAX_FIXTURE_BYTES,
        "corpus fixture {} is {length} bytes, above the {MAX_FIXTURE_BYTES} byte ceiling this gate reads; raise the ceiling deliberately rather than letting the file go ungraded",
        relative(path)
    );
    fs::read(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "corpus fixture {} must be readable: {error}",
            path.display()
        )
    })
}

fn javascript_files(root: &Path) -> Vec<PathBuf> {
    let entries: fs::ReadDir = fs::read_dir(root).unwrap_or_else(|error: std::io::Error| {
        panic!("corpus directory {} is required: {error}", root.display())
    });
    let mut found: Vec<PathBuf> = Vec::new();
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry: fs::DirEntry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            found.extend(javascript_files(&path));
        } else if path
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext == "js")
        {
            found.push(path);
        }
    }
    found
}

fn sample_fixtures() -> Vec<PathBuf> {
    let samples: PathBuf = corpus().join("src/javascript/obfuscator-io-samples");
    let mut found: Vec<PathBuf> = javascript_files(&samples.join("presets"));
    found.extend(javascript_files(&samples.join("controls")));
    found
}

fn negative_files() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for family in NEGATIVE_FAMILIES {
        found.extend(javascript_files(&corpus().join("js").join(family)));
    }
    found
}

#[test]
fn every_obfuscator_io_sample_routes_to_the_obfuscator_io_pipeline() {
    let fixtures: Vec<PathBuf> = sample_fixtures();
    assert!(
        fixtures.len() >= SAMPLE_FIXTURE_FLOOR,
        "the obfuscator.io sample set must carry at least {SAMPLE_FIXTURE_FLOOR} fixtures; found {}",
        fixtures.len()
    );
    let mut misrouted: Vec<String> = Vec::new();
    for path in &fixtures {
        let detection: Detection = detect(&read_bounded(path));
        if detection.family != JsObfuscator::ObfuscatorIo {
            misrouted.push(format!(
                "{} routed as {:?}",
                relative(path),
                detection.family
            ));
        }
    }
    assert!(
        misrouted.is_empty(),
        "every obfuscator.io sample must select the obfuscator.io pipeline, whatever its identifier generator; misrouted {misrouted:?}"
    );
}

#[test]
fn no_other_javascript_family_routes_to_the_obfuscator_io_pipeline() {
    let files: Vec<PathBuf> = negative_files();
    assert!(
        files.len() >= NEGATIVE_FILE_FLOOR,
        "the negative population must carry at least {NEGATIVE_FILE_FLOOR} files across {} families; found {}",
        NEGATIVE_FAMILIES.len(),
        files.len()
    );
    let mut claimed: Vec<String> = Vec::new();
    for path in &files {
        let detection: Detection = detect(&read_bounded(path));
        if detection.family == JsObfuscator::ObfuscatorIo {
            claimed.push(relative(path));
        }
    }
    assert!(
        claimed.is_empty(),
        "no minifier, bundler or other obfuscator output may select the obfuscator.io pipeline; claimed {claimed:?}"
    );
}

#[test]
fn obfuscator_io_reporting_detection_holds_its_declared_false_positives() {
    let files: Vec<PathBuf> = negative_files();
    assert!(
        files.len() >= NEGATIVE_FILE_FLOOR,
        "the negative population must carry at least {NEGATIVE_FILE_FLOOR} files; found {}",
        files.len()
    );
    let mut matched: Vec<String> = Vec::new();
    for path in &files {
        let source: String = String::from_utf8_lossy(&read_bounded(path)).into_owned();
        if obfuscator_io_detect(&source).matched {
            matched.push(relative(path));
        }
    }
    let mut declared: Vec<String> = REPORTING_FALSE_POSITIVES
        .iter()
        .map(|entry: &&str| (*entry).to_owned())
        .collect();
    declared.sort();
    matched.sort();
    assert_eq!(
        matched, declared,
        "the reporting detector must claim exactly its declared false positives; if this fires because a marker got more precise, shorten REPORTING_FALSE_POSITIVES in the same commit"
    );
}
