#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "common/build_records.rs"]
mod build_records;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use disrobe_pass_wasm_deob::{
    NameStrategy, WasmObfuscator, detect, fingerprint_module, obfuscated_name_style,
    strip_name_section, strip_obfuscated_names,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use build_records::{RecordSet, recorded_text};

const RECORDS_SCHEMA: &str = "disrobe.real-tool-outputs/v1";
const RUNNER_OUTPUTS: usize = 30;
const TOOL_COMMIT: &str = "d752a3ded5638b94d4db4630ade0d1b8d3c01fb1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    schema: String,
    tool: String,
    tool_url: String,
    tool_commit: String,
    tool_tree: String,
    runtime: String,
    recipe: String,
    repository_commit: String,
    runner_image: String,
    workflow_run: String,
    output: Vec<RunnerOutput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerOutput {
    path: String,
    sha256: String,
    bytes: u64,
    input: String,
    input_sha256: String,
    command: String,
    behaviour: String,
    input_wasm_sha256: String,
    written_style: String,
    written_style_note: Option<String>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn fixture_dir() -> PathBuf {
    repo_root().join("corpus/wasm/obf/name_obfuscator")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn load_records() -> Records {
    let path: PathBuf = fixture_dir().join("records.toml");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|error: toml::de::Error| panic!("parse {}: {error}", path.display()))
}

fn checked_relative(path: &str) -> PathBuf {
    let parsed: PathBuf = PathBuf::from(path);
    assert!(
        !parsed.is_absolute()
            && parsed
                .components()
                .all(|component: Component<'_>| matches!(component, Component::Normal(_))),
        "runner fixture path must be a relative normal path: {path}"
    );
    parsed
}

fn style(label: &str) -> NameStrategy {
    match label {
        "hex" => NameStrategy::Hex,
        "alphanumeral" => NameStrategy::Alphanum,
        "alternating" => NameStrategy::Homoglyph,
        other => panic!("unknown wasm-name-obfuscator style {other}"),
    }
}

fn clean_reference_path(record: &RunnerOutput) -> PathBuf {
    let source_name: &str = Path::new(&record.input)
        .file_name()
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        .unwrap_or_else(|| panic!("{} has no UTF-8 file name", record.input));
    let clean_name: &str = source_name
        .strip_suffix(".wat")
        .unwrap_or_else(|| panic!("{} is not a WAT input", record.input));
    fixture_dir()
        .join("clean")
        .join(format!("{clean_name}.wasm"))
}

fn clean_reference(record: &RunnerOutput) -> Vec<u8> {
    let relative: &str = record
        .input
        .strip_prefix("corpus/wasm/obf/")
        .unwrap_or_else(|| panic!("{} is outside the recorded wasm corpus", record.input));
    let source: String = recorded_text(RecordSet::Corpus, relative);
    assert_eq!(
        sha256_hex(source.as_bytes()),
        record.input_sha256,
        "{} changed since the pinned runner used it",
        record.input
    );
    let path: PathBuf = clean_reference_path(record);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        record.input_wasm_sha256,
        "{} differs from the pinned wasm-tools clean reference",
        path.display()
    );
    bytes
}

fn body_identity(bytes: &[u8]) -> Vec<(u32, [u8; 32], usize)> {
    fingerprint_module(bytes)
        .unwrap_or_else(|error| panic!("fingerprint wasm reference: {error}"))
        .into_iter()
        .map(|fingerprint| {
            (
                fingerprint.defined_index,
                fingerprint.exact_hash,
                fingerprint.opcode_len,
            )
        })
        .collect()
}

fn assert_same_bodies(reference: &[u8], candidate: &[u8]) -> Result<(), String> {
    let expected: Vec<(u32, [u8; 32], usize)> = body_identity(reference);
    let actual: Vec<(u32, [u8; 32], usize)> = body_identity(candidate);
    (expected == actual).then_some(()).ok_or_else(|| {
        format!("defined body fingerprints differ: expected {expected:?}, recovered {actual:?}")
    })
}

#[test]
fn records_pin_all_runner_outputs_and_clean_wasm_provenance() {
    let records: Records = load_records();
    assert_eq!(records.schema, RECORDS_SCHEMA);
    assert_eq!(records.tool, "wasm-name-obfuscator");
    assert_eq!(
        records.tool_url,
        "https://github.com/abcxff/wasm-name-obfuscator"
    );
    assert_eq!(records.tool_commit, TOOL_COMMIT);
    assert_eq!(records.tool_tree.len(), 40);
    assert!(records.runtime.contains("wasm-tools 1.250.0"));
    assert!(repo_root().join(&records.recipe).is_file());
    assert_eq!(records.repository_commit.len(), 40);
    assert!(!records.runner_image.is_empty());
    assert!(records.workflow_run.starts_with("https://github.com/"));
    assert_eq!(records.output.len(), RUNNER_OUTPUTS);

    let expected: BTreeSet<String> = records
        .output
        .iter()
        .map(|record: &RunnerOutput| record.path.clone())
        .collect();
    assert_eq!(
        expected.len(),
        RUNNER_OUTPUTS,
        "runner records duplicate a path"
    );
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixture_dir())
        .expect("list wasm-name-obfuscator fixtures")
        .filter_map(|entry: std::io::Result<std::fs::DirEntry>| {
            let entry: std::fs::DirEntry = entry.expect("fixture directory entry");
            entry
                .file_type()
                .expect("fixture directory entry type")
                .is_file()
                .then(|| {
                    entry
                        .file_name()
                        .into_string()
                        .expect("fixture name is UTF-8")
                })
        })
        .filter(|name: &String| name != "records.toml")
        .collect();
    assert_eq!(on_disk, expected, "every fixture requires a runner record");

    let expected_clean: BTreeSet<PathBuf> =
        records.output.iter().map(clean_reference_path).collect();
    let actual_clean: BTreeSet<PathBuf> = std::fs::read_dir(fixture_dir().join("clean"))
        .expect("list pinned wasm-tools clean references")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry.expect("clean reference entry").path()
        })
        .collect();
    assert_eq!(
        actual_clean, expected_clean,
        "clean reference inventory drifted"
    );

    for record in &records.output {
        let fixture: PathBuf = fixture_dir().join(checked_relative(&record.path));
        let bytes: Vec<u8> = std::fs::read(&fixture)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", fixture.display()));
        assert_eq!(bytes.len() as u64, record.bytes, "{}", record.path);
        assert_eq!(sha256_hex(&bytes), record.sha256, "{}", record.path);
        assert_eq!(record.behaviour, "same", "{}", record.path);
        assert!(
            record
                .command
                .starts_with("node run-obfuscator.js obfuscate.js ")
        );
        assert_eq!(record.input_wasm_sha256.len(), 64, "{}", record.path);
        assert!(
            record
                .input_wasm_sha256
                .bytes()
                .all(|byte: u8| byte.is_ascii_hexdigit()),
            "{} has an invalid clean wasm digest",
            record.path
        );
        let _reference: Vec<u8> = clean_reference(record);
        if let Some(note) = &record.written_style_note {
            assert!(note.contains("default hex style"), "{}", record.path);
        }
    }
}

#[test]
fn every_runner_output_strips_to_the_pinned_clean_body_reference() {
    let records: Records = load_records();
    let mut styles_per_program: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in &records.output {
        let fixture: PathBuf = fixture_dir().join(checked_relative(&record.path));
        let obfuscated: Vec<u8> = std::fs::read(&fixture)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", fixture.display()));
        let expected_style: NameStrategy = style(&record.written_style);
        assert_eq!(
            obfuscated_name_style(&obfuscated).expect("runner fixture parses"),
            Some(expected_style),
            "{} must carry a fully recognizable generated name section",
            record.path
        );
        let detection = detect(&obfuscated).expect("detect runner fixture");
        assert_eq!(
            detection.obfuscator,
            WasmObfuscator::WasmNameObfuscator,
            "{} must classify from its generated name section",
            record.path
        );
        assert_eq!(
            detection.name_strategy,
            Some(expected_style),
            "{}",
            record.path
        );
        assert!(
            detection
                .markers
                .contains(&format!("generated-name-section:{}", record.written_style)),
            "{} lacks its generated-name-section marker: {:?}",
            record.path,
            detection.markers
        );
        let (stripped, stats) = strip_obfuscated_names(&obfuscated)
            .unwrap_or_else(|error| panic!("strip {}: {error}", record.path));
        assert!(
            stats.function_names_dropped > 0,
            "{} has no generated function names to remove",
            record.path
        );
        assert!(
            stripped.len() < obfuscated.len(),
            "{} retained its name section",
            record.path
        );
        let reference: Vec<u8> = clean_reference(record);
        assert_eq!(
            stripped,
            strip_name_section(&reference).expect("strip reference names"),
            "{} changed bytes outside the generated name section",
            record.path
        );
        assert_same_bodies(&reference, &stripped)
            .unwrap_or_else(|error: String| panic!("{}: {error}", record.path));

        let (program, requested_style): (&str, &str) = record
            .path
            .strip_suffix(".wasm")
            .and_then(|stem: &str| stem.rsplit_once('.'))
            .unwrap_or_else(|| panic!("{} does not have a style suffix", record.path));
        styles_per_program
            .entry(program.to_owned())
            .or_default()
            .insert(requested_style.to_owned());
    }
    assert_eq!(styles_per_program.len(), 10);
    for (program, styles) in styles_per_program {
        assert_eq!(
            styles,
            BTreeSet::from([
                "alternating".to_owned(),
                "alphanumeral".to_owned(),
                "hex".to_owned()
            ]),
            "{program} is missing a requested runner style"
        );
    }
}

#[test]
fn reference_comparison_rejects_a_clean_body_mutation() {
    let records: Records = load_records();
    let record: &RunnerOutput = records
        .output
        .iter()
        .find(|record: &&RunnerOutput| record.path == "callind_dispatch.hex.wasm")
        .expect("callind_dispatch hex runner fixture");
    let clean: Vec<u8> = clean_reference(record);
    let source_relative: &str = record
        .input
        .strip_prefix("corpus/wasm/obf/")
        .expect("recorded source remains in corpus");
    let source: String = recorded_text(RecordSet::Corpus, source_relative);
    let mutated_source: String = source.replacen("i32.const 16", "i32.const 17", 1);
    assert_ne!(
        mutated_source, source,
        "mutation control must alter the clean reference"
    );
    let mutated: Vec<u8> = wat::parse_str(&mutated_source).expect("mutated reference assembles");
    assert!(
        assert_same_bodies(&clean, &mutated).is_err(),
        "the body oracle must reject a clean-reference constant mutation"
    );
}
