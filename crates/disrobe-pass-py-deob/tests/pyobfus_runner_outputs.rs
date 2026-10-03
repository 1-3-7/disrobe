#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_deob::obfuscators::pyobfus::PyobfusPass;
use disrobe_pass_py_deob::obfuscators::{ObfuscatorPass, PeelOutcome, Quality};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const OUTPUTS: usize = 15;
const TOOL_FAILURES: usize = 3;
const PYTHON_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Deserialize)]
struct BuildRecord {
    outputs: Vec<RunnerOutput>,
    recipe: String,
    repository_commit: String,
    runner_image: String,
    tool: Tool,
    workflow_run: String,
}

#[derive(Deserialize)]
struct Tool {
    name: String,
    runtime: String,
    url: String,
    version: String,
}

#[derive(Deserialize)]
struct RunnerOutput {
    behaviour: String,
    command: String,
    input: String,
    input_sha256: String,
    output: Option<String>,
    output_bytes: Option<u64>,
    output_sha256: Option<String>,
}

struct Fixture<'a> {
    record: &'a RunnerOutput,
    bytes: Vec<u8>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_dir() -> PathBuf {
    repo_root().join("corpus/python/pyobfus/real")
}

fn load_record() -> BuildRecord {
    let path: PathBuf = fixture_dir().join("build-record.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error: serde_json::Error| panic!("{}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn local_name(record: &RunnerOutput) -> &str {
    record
        .output
        .as_deref()
        .and_then(|path: &str| Path::new(path).file_name())
        .and_then(|name: &std::ffi::OsStr| name.to_str())
        .unwrap_or_else(|| panic!("{} has no output file", record.command))
}

fn fixtures(record: &BuildRecord) -> Vec<Fixture<'_>> {
    record
        .outputs
        .iter()
        .filter(|output: &&RunnerOutput| output.behaviour == "same")
        .map(|record: &RunnerOutput| {
            let path: PathBuf = fixture_dir().join(local_name(record));
            let bytes: Vec<u8> = std::fs::read(&path)
                .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
            assert_eq!(
                Some(bytes.len() as u64),
                record.output_bytes,
                "{}",
                record.command
            );
            assert_eq!(
                Some(sha256_hex(&bytes)),
                record.output_sha256,
                "{}",
                record.command
            );
            Fixture { record, bytes }
        })
        .collect()
}

fn python_312() -> PathBuf {
    common::require_python_312()
}

fn run_tool(command: CommandSpec, label: &str) -> ToolOutput {
    let output: ToolOutput =
        tool_output(command).unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(!output.timed_out, "{label} timed out");
    output
}

fn execute(python: &Path, fixture: &Fixture<'_>, source: &str) -> (bool, String, String) {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pyobfus_reexec").expect("scratch");
    let recovered: PathBuf = scratch.path().join("recovered.py");
    std::fs::write(&recovered, source).expect("write recovered source");
    let output: ToolOutput = run_tool(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-X")
            .arg("utf8")
            .arg(&recovered)
            .current_dir(repo_root())
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1"),
        &fixture.record.command,
    );
    (output.success, output.stdout_text(), output.stderr_text())
}

#[test]
fn runner_record_pins_real_outputs_and_upstream_failures() {
    let record: BuildRecord = load_record();
    assert_eq!(record.recipe, "pyobfus");
    assert_eq!(record.tool.name, "pyobfus");
    assert!(
        record
            .tool
            .url
            .starts_with("https://pypi.org/project/pyobfus/")
    );
    assert!(record.tool.version.contains("pyobfus 0.5.30"));
    assert!(record.tool.runtime.starts_with("Python 3.12."));
    assert_eq!(record.repository_commit.len(), 40);
    assert!(!record.runner_image.is_empty());
    assert!(record.workflow_run.starts_with("https://github.com/"));
    assert!(
        repo_root()
            .join(".github/real-tools")
            .join(format!("{}.sh", record.recipe))
            .is_file()
    );

    let fixtures: Vec<Fixture<'_>> = fixtures(&record);
    assert_eq!(fixtures.len(), OUTPUTS);
    let expected: BTreeSet<String> = fixtures
        .iter()
        .map(|fixture: &Fixture<'_>| local_name(fixture.record).to_owned())
        .collect();
    let actual: BTreeSet<String> = std::fs::read_dir(fixture_dir())
        .expect("list fixture directory")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("directory entry")
                .file_name()
                .into_string()
                .expect("utf-8 fixture name")
        })
        .filter(|name: &String| name != "build-record.json")
        .collect();
    assert_eq!(actual, expected);
    let failures: Vec<&RunnerOutput> = record
        .outputs
        .iter()
        .filter(|output: &&RunnerOutput| output.behaviour == "tool-failed")
        .collect();
    assert_eq!(failures.len(), TOOL_FAILURES);
    for failure in failures {
        assert_eq!(failure.output, None, "{}", failure.command);
        assert!(failure.command.contains("closures_nonlocal_global.py"));
    }
    for fixture in fixtures {
        let input: Vec<u8> = std::fs::read(repo_root().join(&fixture.record.input))
            .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", fixture.record.input));
        assert_eq!(sha256_hex(&input), fixture.record.input_sha256);
        assert!(fixture.record.command.starts_with("pyobfus "));
    }
}

#[test]
fn recovered_runner_sources_reexecute_like_their_authored_inputs() {
    let record: BuildRecord = load_record();
    let python: PathBuf = python_312();
    for fixture in fixtures(&record) {
        let report = PyobfusPass.detect(&fixture.bytes);
        assert!(report.matched, "{}: {report:?}", fixture.record.command);
        assert!(
            report
                .markers
                .iter()
                .any(|marker: &String| marker == "pyobfus-generated-source"),
            "{}: {report:?}",
            fixture.record.command
        );
        let outcome: PeelOutcome = PyobfusPass
            .peel(&fixture.bytes)
            .unwrap_or_else(|error| panic!("{}: {error:?}", fixture.record.command));
        assert_eq!(outcome.quality, Quality::Partial);
        let generated: &str = std::str::from_utf8(&fixture.bytes).expect("generated UTF-8");
        let body: String = generated.split_inclusive('\n').skip(4).collect();
        assert_eq!(outcome.recovered_source, body, "{}", fixture.record.command);
        assert!(!outcome.recovered_source.contains("pyobfus:generated"));
        assert_ne!(
            outcome.recovered_source.as_bytes(),
            fixture.bytes.as_slice()
        );
        let original: String = std::fs::read_to_string(repo_root().join(&fixture.record.input))
            .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", fixture.record.input));
        let expected: (bool, String, String) = execute(&python, &fixture, &original);
        assert!(expected.0, "{}", expected.2);
        let recovered: (bool, String, String) =
            execute(&python, &fixture, &outcome.recovered_source);
        assert_eq!(recovered, expected, "{}", fixture.record.command);
    }
}

#[test]
fn changing_a_recovered_literal_turns_the_runtime_oracle_red() {
    let record: BuildRecord = load_record();
    let python: PathBuf = python_312();
    let fixture: Fixture<'_> = fixtures(&record)
        .into_iter()
        .find(|fixture: &Fixture<'_>| fixture.record.input.ends_with("pyc_zipper/sample.py"))
        .expect("sample runner output");
    let recovered: String = PyobfusPass
        .peel(&fixture.bytes)
        .expect("peel sample")
        .recovered_source;
    let changed: String = recovered.replacen("hello, ", "hullo, ", 1);
    assert_ne!(changed, recovered);
    let original: String = std::fs::read_to_string(repo_root().join(&fixture.record.input))
        .expect("read authored sample");
    let expected: (bool, String, String) = execute(&python, &fixture, &original);
    assert!(expected.0);
    assert_ne!(execute(&python, &fixture, &changed), expected);
}
