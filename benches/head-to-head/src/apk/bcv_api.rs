use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::subprocess::CapturedOutput;

use super::{
    MAIN_CLASS_FILE, MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, ProbeScore, ProvenancedExternalTool,
    ToolInvocation, ToolScore, VersionCapture, bounded_error_text, combined_output,
    external_probe_score, read_bounded_file, read_bounded_string, retain_probe_score,
    retain_sources_and_score, retain_tool_provenance, run, sha256_hex, version_capture_checked,
    write_new_file,
};

const HARNESS: &str = include_str!("../../adapters/BytecodeViewerHarness.java");

pub(super) fn score(
    javac: &Path,
    java: &Path,
    jar: &Path,
    jar_bytes: &[u8],
    denominator: usize,
    artifact: &Path,
    tool: &ProvenancedExternalTool,
) -> std::result::Result<ToolScore, String> {
    std::fs::create_dir(artifact)
        .map_err(|error| format!("creating Bytecode Viewer API artifact: {error}"))?;
    let harness: PathBuf = artifact.join("BytecodeViewerHarness.java");
    write_new_file(&harness, HARNESS.as_bytes())?;
    let classes: PathBuf = artifact.join("classes");
    let build: PathBuf = artifact.join("harness-build");
    let user_home: PathBuf = artifact.join("user-home");
    let temporary: PathBuf = artifact.join("temporary");
    for directory in [&classes, &build, &user_home, &temporary] {
        std::fs::create_dir(directory)
            .map_err(|error| format!("creating API runtime directory: {error}"))?;
    }
    let tool_bytes: Vec<u8> = read_bounded_file(&tool.executable, MAX_FIXTURE_BYTES)
        .map_err(|error| error.to_string())?;
    let mut inputs: Vec<(String, String)> = vec![
        ("EdgeCases-baseline.jar".to_owned(), sha256_hex(jar_bytes)),
        ("bytecode-viewer.jar".to_owned(), sha256_hex(&tool_bytes)),
        (
            "BytecodeViewerHarness.java".to_owned(),
            sha256_hex(HARNESS.as_bytes()),
        ),
    ];
    let compile_args: Vec<String> = vec![
        "-J-Xmx512m".to_owned(),
        "-proc:none".to_owned(),
        "-cp".to_owned(),
        tool.executable.to_string_lossy().into_owned(),
        "-d".to_owned(),
        classes.to_string_lossy().into_owned(),
        harness.to_string_lossy().into_owned(),
    ];
    let refs: Vec<&str> = compile_args.iter().map(String::as_str).collect();
    let compiler_version: VersionCapture = version_capture_checked(javac, &["-version"], None)?;
    let compiled: CapturedOutput = run(javac, &refs)?;
    if compiled.exit_code == Some(0) {
        for name in [
            "BytecodeViewerHarness.class",
            "BytecodeViewerHarness$HeadlessCfr.class",
        ] {
            let bytes: Vec<u8> = read_bounded_file(&classes.join(name), MAX_TEXT_BYTES)
                .map_err(|error| format!("reading compiled API harness {name}: {error}"))?;
            inputs.push((name.to_owned(), sha256_hex(&bytes)));
        }
    }
    retain_tool_provenance(
        &build,
        &ToolInvocation {
            route: "bytecode-viewer-api-harness-javac",
            executable: javac,
            args: &compile_args,
            environment: &[],
            output: Some(&compiled),
        },
        &["-version"],
        &compiler_version,
        &inputs,
    )?;
    if compiled.exit_code != Some(0) {
        return Ok(ToolScore::miss(
            denominator,
            format!(
                "Bytecode Viewer API harness compile failed: {}",
                bounded_error_text(&combined_output(&compiled))
            ),
        ));
    }
    let output: PathBuf = artifact.join("EdgeCases.java");
    let classpath: std::ffi::OsString =
        std::env::join_paths([classes.as_path(), tool.executable.as_path()])
            .map_err(|error| error.to_string())?;
    let args: Vec<String> = vec![
        "-Djava.awt.headless=true".to_owned(),
        "-Xmx512m".to_owned(),
        format!("-Duser.home={}", user_home.display()),
        format!("-Djava.io.tmpdir={}", temporary.display()),
        "-cp".to_owned(),
        classpath.to_string_lossy().into_owned(),
        "BytecodeViewerHarness".to_owned(),
        jar.to_string_lossy().into_owned(),
        output.to_string_lossy().into_owned(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran: CapturedOutput = run(java, &refs)?;
    let version: VersionCapture = version_capture_checked(java, &["-version"], None)?;
    retain_tool_provenance(
        artifact,
        &ToolInvocation {
            route: "bytecode-viewer-cfr-api-empty-options",
            executable: java,
            args: &args,
            environment: &[],
            output: Some(&ran),
        },
        &["-version"],
        &version,
        &inputs,
    )?;
    if ran.exit_code != Some(0) {
        return Ok(ToolScore::miss(
            denominator,
            bounded_error_text(&combined_output(&ran)),
        ));
    }
    let source: String = read_bounded_string(&output, MAX_TEXT_BYTES)
        .map_err(|error| format!("reading Bytecode Viewer API output: {error}"))?;
    let sources: BTreeMap<String, String> = BTreeMap::from([(MAIN_CLASS_FILE.to_owned(), source)]);
    let probe: ProbeScore = external_probe_score(javac, java, jar, &sources, artifact);
    retain_probe_score(artifact, &probe)?;
    retain_sources_and_score(javac, &sources, denominator, artifact)
}
