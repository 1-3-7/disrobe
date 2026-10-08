#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;
use serde_json::Value as Json;

const PROGRAM: &str = "corpus/native/anti-analysis/runtime/is_debugger_present.c";
const CHECK_LINE: &str = "check=is_debugger_present result=";

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn compile_armed(dir: &Path) -> PathBuf {
    let source: PathBuf = workspace_root().join(PROGRAM);
    assert!(
        source.is_file(),
        "{} is a tracked fixture",
        source.display()
    );
    let exe: PathBuf = dir.join("armed.exe");
    let output: Output = Command::new("gcc")
        .args(["-O0", "-DARMED", "-o"])
        .arg(&exe)
        .arg(&source)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("gcc is required to build the authored anti-debug program: {error}")
        });
    assert!(
        output.status.success(),
        "gcc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

fn result_of(exe: &Path) -> String {
    let output: Output = Command::new(exe)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("{} failed to start: {error}", exe.display())
        });
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line: &&str| line.starts_with(CHECK_LINE))
        .unwrap_or_else(|| panic!("{} printed no result line", exe.display()))
        .to_owned()
}

fn decompile(input: &Path, out: &Path, neutralize: Option<&str>) -> Output {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command
        .args(["native", "decompile"])
        .arg(input)
        .arg("--out")
        .arg(out);
    if let Some(mode) = neutralize {
        command.args(["--neutralize", mode]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe native decompile: {error}"))
}

fn report(out: &Path) -> Json {
    let path: PathBuf = out.join("neutralization.json");
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no report at {}: {error}", path.display()));
    serde_json::from_str(&text).expect("neutralization.json is json")
}

#[test]
fn neutralize_apply_writes_a_patched_copy_that_takes_the_clean_path_and_keeps_the_input() {
    let scratch: ScratchDir = ScratchDir::create("cli-native-neutralize").expect("scratch dir");
    let input: PathBuf = compile_armed(scratch.path());
    let before: Vec<u8> = std::fs::read(&input).expect("read input");
    assert_eq!(result_of(&input), format!("{CHECK_LINE}debugged"));

    let out: PathBuf = scratch.path().join("apply");
    let run: Output = decompile(&input, &out, Some("apply"));
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("native neutralize (apply)"),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        std::fs::read(&input).expect("reread input"),
        before,
        "the input file is never modified"
    );
    let patched: PathBuf = out.join("armed.neutralized.exe");
    assert!(patched.is_file(), "{} was not written", patched.display());
    assert_eq!(result_of(&patched), format!("{CHECK_LINE}clean"));

    let document: Json = report(&out);
    assert_eq!(document["mode"], "apply");
    let applied: &Vec<Json> = document["report"]["applied"]
        .as_array()
        .expect("applied list");
    assert!(
        applied
            .iter()
            .any(|p: &Json| p["check"] == "is-debugger-present"),
        "{document:#}"
    );
    assert!(
        document["report"]["declined"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

#[test]
fn neutralize_skip_reports_the_plan_and_writes_no_copy() {
    let scratch: ScratchDir =
        ScratchDir::create("cli-native-neutralize-skip").expect("scratch dir");
    let input: PathBuf = compile_armed(scratch.path());
    let out: PathBuf = scratch.path().join("skip");
    let run: Output = decompile(&input, &out, Some("skip"));
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("stays reported as detected"),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(!out.join("armed.neutralized.exe").exists());
    let document: Json = report(&out);
    assert!(document["output"].is_null());
    assert!(
        document["report"]["applied"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert!(
        document["report"]["skipped"]
            .as_array()
            .is_some_and(|s: &Vec<Json>| s
                .iter()
                .any(|p: &Json| p["check"] == "is-debugger-present")),
        "{document:#}"
    );
}

#[test]
fn without_the_flag_a_non_terminal_run_neither_plans_nor_patches() {
    let scratch: ScratchDir =
        ScratchDir::create("cli-native-neutralize-default").expect("scratch dir");
    let input: PathBuf = compile_armed(scratch.path());
    let out: PathBuf = scratch.path().join("default");
    let _ = decompile(&input, &out, None);
    assert!(!out.join("neutralization.json").exists());
    assert!(!out.join("armed.neutralized.exe").exists());
}
