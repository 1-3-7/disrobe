#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{decompile_class_named, extract_jar, parse_classfile};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::common;

const RECORD: &str = include_str!("../../../../corpus/jvm/obfuscators/jbco/real/build-record.json");
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
const TOOL_CAPTURE_BYTES: usize = 1024 * 1024;

const PARTIALS: &[&str] = &[
    "Calculator.names.jar",
    "Sample.flow.jar",
    "SwitchDispatch.flow.jar",
    "SwitchDispatch.names.jar",
];

#[derive(Deserialize)]
struct BuildRecord {
    files: BTreeMap<String, String>,
    outputs: Vec<RecordOutput>,
    recipe: String,
    workflow_run: String,
    tool: RecordTool,
}

#[derive(Deserialize)]
struct RecordTool {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct RecordOutput {
    behaviour: String,
    input: String,
    input_sha256: String,
    output: Option<String>,
    output_bytes: Option<usize>,
    output_sha256: Option<String>,
}

struct Fixture {
    jar: &'static str,
    source: &'static str,
    main: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        jar: "Calculator.names.jar",
        source: "obfuscators/yguard/gauntlet/Calculator.java",
        main: "com.example.app.Calculator",
    },
    Fixture {
        jar: "Sample.flow.jar",
        source: "obfuscators/jbco/gauntlet/Sample.java",
        main: "com.example.app.Sample",
    },
    Fixture {
        jar: "Sample.names.jar",
        source: "obfuscators/jbco/gauntlet/Sample.java",
        main: "com.example.app.Sample",
    },
    Fixture {
        jar: "SwitchDispatch.flow.jar",
        source: "evalshapes/SwitchDispatch.java",
        main: "com.disrobe.bench.SwitchDispatch",
    },
    Fixture {
        jar: "SwitchDispatch.names.jar",
        source: "evalshapes/SwitchDispatch.java",
        main: "com.disrobe.bench.SwitchDispatch",
    },
];

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("jvm");
    for part in parts {
        path.push(part);
    }
    path
}

fn fixture_path(name: &str) -> PathBuf {
    corpus(&["obfuscators", "jbco", "real", name])
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn run_tool(command: CommandSpec, label: &str) -> ToolOutput {
    let output: ToolOutput = tool_output(command)
        .unwrap_or_else(|error: ToolError| panic!("{label} could not start: {error}"));
    assert!(!output.timed_out, "{label} timed out");
    output
}

fn run(java: &Path, classpath: &Path, main: &str) -> ToolOutput {
    run_tool(
        CommandSpec::new(java, TOOL_TIMEOUT)
            .arg("-cp")
            .arg(classpath)
            .arg(main)
            .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES),
        &format!("run {main} from {}", classpath.display()),
    )
}

fn compile_sources(javac: &Path, output: &Path, sources: &[PathBuf]) -> Result<(), String> {
    std::fs::create_dir_all(output).expect("create javac output directory");
    let mut command: CommandSpec = CommandSpec::new(javac, TOOL_TIMEOUT)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-d")
        .arg(output)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES);
    for source in sources {
        command = command.arg(source);
    }
    let output: ToolOutput = run_tool(command, "javac");
    if output.success {
        Ok(())
    } else {
        Err(format!("{}{}", output.stdout_text(), output.stderr_text()))
    }
}

fn recovered_sources(jar: &[u8], root: &Path) -> Result<Vec<PathBuf>, String> {
    let extracted = extract_jar(jar).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for (entry, bytes) in extracted.classes {
        let class = parse_classfile(&bytes).map_err(|error| format!("parse {entry}: {error}"))?;
        let (name, recovered) = decompile_class_named(&class);
        if recovered.fallback_methods != 0 {
            return Err("recovered source has fallback methods".to_owned());
        }
        let source_name: &str = Path::new(&name)
            .file_name()
            .filter(|file_name: &&std::ffi::OsStr| {
                Path::new(file_name).extension() == Some(std::ffi::OsStr::new("java"))
            })
            .and_then(|file_name: &std::ffi::OsStr| file_name.to_str())
            .filter(|file_name: &&str| *file_name == name)
            .ok_or_else(|| format!("refuse unsafe recovered source path {name:?}"))?;
        let path: PathBuf = root.join(source_name);
        std::fs::write(&path, recovered.source)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn partial_reason(fixture: &Fixture, javac: &Path, java: &Path) -> Option<String> {
    let scratch: ScratchDir = ScratchDir::create("jbco_runner_output_grade").expect("scratch");
    let root: &Path = scratch.path();
    let original_classes: PathBuf = root.join("original");
    let recovered_classes: PathBuf = root.join("recovered");
    let original: PathBuf = corpus(&[fixture.source]);
    compile_sources(javac, &original_classes, &[original])
        .unwrap_or_else(|error| panic!("original {} did not compile: {error}", fixture.source));
    let original: ToolOutput = run(java, &original_classes, fixture.main);
    assert!(
        original.success,
        "authored original {} failed: {}",
        fixture.source,
        original.stderr_text()
    );
    let jar: Vec<u8> = std::fs::read(fixture_path(fixture.jar)).expect("read runner fixture");
    let sources: Vec<PathBuf> = match recovered_sources(&jar, &root.join("source")) {
        Ok(sources) => sources,
        Err(reason) => return Some(reason),
    };
    if let Err(error) = compile_sources(javac, &recovered_classes, &sources) {
        return Some(format!("recovered source did not compile: {error}"));
    }
    let recovered: ToolOutput = run(java, &recovered_classes, fixture.main);
    if !recovered.success {
        return Some(format!(
            "recovered source exited {:?}: {}",
            recovered.exit_code,
            recovered.stderr_text()
        ));
    }
    if recovered.stdout != original.stdout || recovered.stderr != original.stderr {
        return Some("recovered source output differs from the authored original".to_owned());
    }
    None
}

#[test]
fn runner_record_pins_successes_and_named_tool_failures() {
    let record: BuildRecord = serde_json::from_str(RECORD).expect("parse JBCO runner record");
    assert_eq!(record.recipe, "jbco");
    assert_eq!(record.tool.name, "JBCO (Soot soot.jbco.Main)");
    assert!(record.tool.version.starts_with("Soot 4.7.1 "));
    assert_eq!(
        record.workflow_run,
        "https://github.com/1-3-7/disrobe/actions/runs/37045868043"
    );
    assert_eq!(record.outputs.len(), 9, "runner denominator changed");
    let successes: Vec<&RecordOutput> = record
        .outputs
        .iter()
        .filter(|row| row.behaviour == "same")
        .collect();
    let failures: Vec<&RecordOutput> = record
        .outputs
        .iter()
        .filter(|row| row.behaviour == "tool-failed")
        .collect();
    assert_eq!(successes.len(), 5, "runner success denominator changed");
    assert_eq!(failures.len(), 4, "runner tool-failure denominator changed");
    assert!(failures.iter().all(|row| row.output.is_none()));
    for row in successes {
        let output: &str = row.output.as_deref().expect("successful runner output");
        let name: &str = output.strip_prefix("files/").expect("runner output path");
        let bytes: Vec<u8> =
            std::fs::read(fixture_path(name)).expect("read committed runner output");
        assert_eq!(bytes.len(), row.output_bytes.expect("runner output bytes"));
        assert_eq!(
            sha256(&bytes),
            row.output_sha256.as_deref().expect("runner hash")
        );
        assert_eq!(record.files.get(output), row.output_sha256.as_ref());
        let input: &str = row
            .input
            .strip_prefix("corpus/jvm/")
            .expect("runner input is in the JVM corpus");
        let authored: Vec<u8> = std::fs::read(corpus(&[input])).expect("read authored input");
        assert_eq!(sha256(&authored), row.input_sha256);
    }
}

#[test]
fn recovered_jbco_sources_are_exactly_named_partial_or_equivalent() {
    let javac: PathBuf = common::grader_jdk_tool("javac");
    let java: PathBuf = common::grader_jdk_tool("java");
    let actual: BTreeMap<&str, String> = FIXTURES
        .iter()
        .filter_map(|fixture| {
            partial_reason(fixture, &javac, &java).map(|reason| (fixture.jar, reason))
        })
        .collect();
    let expected: BTreeSet<&str> = PARTIALS.iter().copied().collect();
    let named: BTreeSet<&str> = actual.keys().copied().collect();
    for (name, reason) in &actual {
        eprintln!("{name}: partial: {reason}");
    }
    assert_eq!(
        named, expected,
        "a JBCO runner output must either compile and match its authored original exactly or occupy a named partial bucket"
    );
    assert!(
        actual.values().all(|reason| !reason.is_empty()),
        "every named partial needs an observed compiler or behaviour reason"
    );
}

#[test]
fn authored_source_mutation_turns_the_reference_red() {
    let javac: PathBuf = common::grader_jdk_tool("javac");
    let java: PathBuf = common::grader_jdk_tool("java");
    for fixture in FIXTURES {
        let scratch: ScratchDir = ScratchDir::create("jbco_runner_mutation").expect("scratch");
        let root: &Path = scratch.path();
        let original_source: String =
            std::fs::read_to_string(corpus(&[fixture.source])).expect("read authored source");
        let mutated_source: String =
            original_source.replacen("System.out.println", "System.err.println", 1);
        assert_ne!(original_source, mutated_source, "mutation target missing");
        let source_name: &str = Path::new(fixture.source)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("authored source filename");
        let source_path: PathBuf = root.join(source_name);
        std::fs::write(&source_path, mutated_source).expect("write mutation source");
        let original_dir: PathBuf = root.join("original");
        let mutated_dir: PathBuf = root.join("mutated");
        compile_sources(&javac, &original_dir, &[corpus(&[fixture.source])])
            .expect("compile original");
        compile_sources(&javac, &mutated_dir, &[source_path]).expect("compile mutation");
        let original: ToolOutput = run(&java, &original_dir, fixture.main);
        let mutated: ToolOutput = run(&java, &mutated_dir, fixture.main);
        assert!(original.success);
        assert!(mutated.success);
        assert_ne!(
            (original.stdout, original.stderr),
            (mutated.stdout, mutated.stderr),
            "the reference comparison did not reject a source mutation for {}",
            fixture.jar
        );
    }
}
