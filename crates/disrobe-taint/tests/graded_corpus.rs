#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
static CLI_PATH: OnceLock<PathBuf> = OnceLock::new();

const FLOWING_PROGRAM: &str = r"
#include <stdio.h>
#include <stdlib.h>

__declspec(dllexport) int taint_entry(void) {
    char input[64];
    return system(fgets(input, sizeof input, stdin));
}

int main(void) {
    return taint_entry();
}
";

const OVERWRITTEN_PROGRAM: &str = r#"
#include <stdio.h>
#include <stdlib.h>

__declspec(dllexport) int taint_entry(void) {
    char input[64];
    char * volatile command = fgets(input, sizeof input, stdin);
    command = "dir";
    return system(command);
}

int main(void) {
    return taint_entry();
}
"#;

struct FixtureDirectory {
    path: PathBuf,
}

struct CompiledFixture {
    _directory: FixtureDirectory,
    executable: PathBuf,
}

impl FixtureDirectory {
    fn create(name: &str) -> Self {
        let fixture_id: u64 = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-taint-{name}-{}-{fixture_id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create fixture directory");
        Self { path }
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _result: std::io::Result<()> = fs::remove_dir_all(&self.path);
    }
}

fn compile_program(name: &str, source: &str) -> CompiledFixture {
    let fixture_dir: FixtureDirectory = FixtureDirectory::create(name);
    let source_path: PathBuf = fixture_dir.path.join("fixture.c");
    let executable_path: PathBuf = fixture_dir.path.join("fixture.exe");
    fs::write(&source_path, source).expect("write fixture source");
    let output: Output = Command::new("C:\\Strawberry\\c\\bin\\gcc.exe")
        .args(["-O2", "-fno-builtin"])
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path)
        .output()
        .expect("run gcc");
    assert!(
        output.status.success(),
        "gcc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    CompiledFixture {
        _directory: fixture_dir,
        executable: executable_path,
    }
}

fn workspace_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..\\..")
}

fn build_cli() -> PathBuf {
    let workspace: PathBuf = workspace_path();
    let output: Output = Command::new(env!("CARGO"))
        .current_dir(&workspace)
        .args(["build", "--quiet", "-p", "disrobe-cli"])
        .output()
        .expect("build disrobe CLI");
    assert!(
        output.status.success(),
        "disrobe CLI build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    workspace.join("target\\debug\\disrobe.exe")
}

fn cli_path() -> &'static PathBuf {
    CLI_PATH.get_or_init(build_cli)
}

fn run_taint(fixture: &CompiledFixture) -> String {
    let output: Output = Command::new(cli_path())
        .args(["--json", "taint"])
        .arg(&fixture.executable)
        .args(["--source", "fgets", "--sink", "system"])
        .output()
        .expect("run disrobe taint");
    assert!(
        output.status.success(),
        "disrobe taint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("taint output is utf-8")
}

fn compact_json(value: &str) -> String {
    value
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect()
}

fn finding_count(json: &str) -> usize {
    let compact: String = compact_json(json);
    let prefix: &str = "\"finding_count\":";
    let count: &str = compact
        .split(prefix)
        .nth(1)
        .and_then(|tail: &str| tail.split(',').next())
        .expect("taint JSON carries finding_count");
    count.parse::<usize>().expect("finding_count is numeric")
}

#[test]
fn compiled_fgets_to_system_flow_is_attributed_to_its_exported_function() {
    let fixture: CompiledFixture = compile_program("flowing", FLOWING_PROGRAM);
    let json: String = compact_json(&run_taint(&fixture));
    let count: usize = finding_count(&json);
    assert!(
        count >= 1,
        "pinned native-flow floor is one finding: {json}"
    );
    assert_eq!(
        count, 1,
        "the reference PE has one source-to-sink finding: {json}"
    );
    assert!(
        json.contains("\"function\":\"taint_entry\"")
            && json.contains("\"source_symbol\":\"fgets\"")
            && json.contains("\"sink_symbol\":\"system\""),
        "fgets feeding system must be attributed to taint_entry: {json}"
    );
}

#[test]
fn overwriting_the_fgets_result_before_system_kills_the_native_flow() {
    let fixture: CompiledFixture = compile_program("overwritten", OVERWRITTEN_PROGRAM);
    let json: String = run_taint(&fixture);
    assert!(
        finding_count(&json) == 0,
        "the mutation overwrites the source result before system: {json}"
    );
}
