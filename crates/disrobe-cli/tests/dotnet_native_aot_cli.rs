#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value as Json;

const AOT_IMAGE: &str = "dotnet/HelloAppAot.exe";
const NOT_AOT_IMAGE: &str = "dotnet/HelloApp.r2r.dll";
const MAX_CAPTURE_BYTES: usize = 1 << 20;

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn corpus_path(relative: &str) -> PathBuf {
    workspace_root().join("corpus").join(relative)
}

fn run_native_aot(input: &Path, out: &Path) -> disrobe_core::subprocess::CapturedOutput {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command
        .arg("dotnet")
        .arg("native-aot")
        .arg(input)
        .arg("--out")
        .arg(out)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe: {error}"));
    disrobe_core::subprocess::wait_with_direct_process_output_timeout(
        child,
        Duration::from_secs(90),
        MAX_CAPTURE_BYTES,
    )
    .unwrap_or_else(|| panic!("disrobe dotnet native-aot did not finish within the timeout"))
}

fn recovered_json(image: &str, label: &str) -> (Json, String) {
    let input: PathBuf = corpus_path(image);
    assert!(
        input.is_file(),
        "{label} requires the tracked corpus image {}",
        input.display()
    );
    let dir: PathBuf = std::env::temp_dir().join(format!("disrobe-native-aot-cli-{label}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let out: PathBuf = dir.join("report.json");
    let captured: disrobe_core::subprocess::CapturedOutput = run_native_aot(&input, &out);
    assert_eq!(
        captured.exit_code,
        Some(0),
        "{label} exited {:?}: {}",
        captured.exit_code,
        String::from_utf8_lossy(&captured.stderr)
    );
    let text: String = std::fs::read_to_string(&out)
        .unwrap_or_else(|error| panic!("{label} wrote no report at {}: {error}", out.display()));
    let parsed: Json = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{label} wrote invalid json: {error}"));
    (
        parsed,
        String::from_utf8_lossy(&captured.stdout).into_owned(),
    )
}

#[test]
fn the_subcommand_recovers_a_real_native_aot_image() {
    let (report, stdout): (Json, String) = recovered_json(AOT_IMAGE, "aot");
    assert_eq!(
        report.get("is_native_aot").and_then(Json::as_bool),
        Some(true),
        "HelloAppAot.exe is a NativeAOT image"
    );
    let names: usize = report
        .get("recovered_names")
        .and_then(Json::as_array)
        .map_or(0, Vec::len);
    assert!(names > 0, "a NativeAOT image yields recovered names");
    assert!(
        stdout.contains("native aot:   yes"),
        "the summary must state the verdict, got: {stdout}"
    );
    assert!(
        stdout.contains("signatures:"),
        "the summary must report the signature split, got: {stdout}"
    );
}

#[test]
fn the_json_flag_writes_the_report_to_stdout_and_no_file() {
    let input: PathBuf = corpus_path(AOT_IMAGE);
    assert!(
        input.is_file(),
        "this gate requires the tracked corpus image {}",
        input.display()
    );
    let dir: PathBuf = std::env::temp_dir().join("disrobe-native-aot-cli-json");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let out: PathBuf = dir.join("must-not-appear.json");
    let _ = std::fs::remove_file(&out);

    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command
        .arg("dotnet")
        .arg("native-aot")
        .arg(&input)
        .arg("--out")
        .arg(&out)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe: {error}"));
    let captured: disrobe_core::subprocess::CapturedOutput =
        disrobe_core::subprocess::wait_with_direct_process_output_timeout(
            child,
            Duration::from_secs(90),
            MAX_CAPTURE_BYTES,
        )
        .unwrap_or_else(|| panic!("disrobe dotnet native-aot --json did not finish"));

    assert_eq!(captured.exit_code, Some(0));
    let stdout: String = String::from_utf8_lossy(&captured.stdout).into_owned();
    let parsed: Json = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("--json must emit only json, got {error}: {stdout:.200}"));
    assert_eq!(
        parsed.get("is_native_aot").and_then(Json::as_bool),
        Some(true),
        "--json must carry the same verdict the summary reports"
    );
    assert!(
        !out.exists(),
        "--json must not write a file, but {} appeared",
        out.display()
    );
}

#[test]
fn a_ready_to_run_assembly_is_reported_as_not_native_aot() {
    let (report, stdout): (Json, String) = recovered_json(NOT_AOT_IMAGE, "r2r");
    assert_eq!(
        report.get("is_native_aot").and_then(Json::as_bool),
        Some(false),
        "HelloApp.r2r.dll is ReadyToRun, not NativeAOT, and the subcommand must say so rather than \
         reporting every .NET input as recovered"
    );
    assert!(
        stdout.contains("native aot:   no"),
        "the summary must state the negative verdict, got: {stdout}"
    );
}
