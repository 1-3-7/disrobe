#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

use disrobe_pass_shell::{
    Detection, Dialect, Family, NodeBashObfuscateReport, detect, is_node_bash_obfuscate,
    reverse_node_bash_obfuscate,
};

const BASH_BIN_VAR: &str = "DISROBE_BASH_BIN";
const DASH_BIN_VAR: &str = "DISROBE_DASH_BIN";

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read_corpus(relative: &str) -> String {
    let p: PathBuf = corpus_path(relative);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

fn shell_path(program: &str, binary_var: &str) -> Result<String, String> {
    if let Some(configured) = std::env::var_os(binary_var) {
        let path: PathBuf = configured.into();
        if !path.is_file() {
            return Err(format!(
                "{binary_var} names {}, which is not a file",
                path.display()
            ));
        }
        let selected: String = path
            .canonicalize()
            .map_err(|error: std::io::Error| format!("resolve {binary_var}: {error}"))?
            .to_string_lossy()
            .into_owned();
        return match run_shell(&selected, "exit 0") {
            Ok(output) if output.success => Ok(selected),
            Ok(_) | Err(_) => Err(format!(
                "{binary_var} names a {program} that cannot run `-c exit 0`"
            )),
        };
    }
    match run_shell(program, "exit 0") {
        Ok(output) if output.success => Ok(program.to_owned()),
        Ok(_) | Err(_) => Err(format!(
            "`{program}` is not runnable on PATH and {binary_var} is unset"
        )),
    }
}

fn bash_path() -> Result<String, String> {
    shell_path("bash", BASH_BIN_VAR)
}

fn dash_path() -> Result<String, String> {
    shell_path("dash", DASH_BIN_VAR)
}

struct Observed {
    stdout: Vec<u8>,
    code: Option<i32>,
}

fn run_shell(shell: &str, script: &str) -> Result<ToolOutput, String> {
    let scratch: ScratchDir =
        ScratchDir::create("shell-reference").map_err(|error| error.to_string())?;
    tool_output(
        CommandSpec::new(shell, Duration::from_secs(30))
            .args(["-c", script])
            .current_dir(scratch.path().to_path_buf())
            .reap_descendants_on_exit(),
    )
    .map_err(|error| error.to_string())
}

fn run_script(shell: &str, script: &str) -> Observed {
    let out: ToolOutput = run_shell(shell, script).expect("spawn bounded reference shell");
    assert!(!out.timed_out, "{shell} did not finish the script in 30 s");
    Observed {
        stdout: out.stdout,
        code: out.exit_code,
    }
}

fn assert_exec_equivalent(shell: &str, original: &str, recovered: &str, label: &str) {
    let truth: Observed = run_script(shell, original);
    let got: Observed = run_script(shell, recovered);
    assert_eq!(
        got.stdout,
        truth.stdout,
        "[{label}] recovered stdout differs from ground-truth original\noriginal-stdout: {ot}\nrecovered-stdout: {gt}\nrecovered-script:\n{recovered}",
        ot = String::from_utf8_lossy(&truth.stdout),
        gt = String::from_utf8_lossy(&got.stdout),
    );
    assert_eq!(
        got.code, truth.code,
        "[{label}] recovered exit code differs from ground truth"
    );
}

#[test]
fn detection_classifies_node_bash_obfuscate() {
    let obf: String = read_corpus("bash/node-bash-obfuscate/obfuscated_chunk4.sh");
    assert!(is_node_bash_obfuscate(&obf));
    let det: Detection = detect(obf.as_bytes());
    assert_eq!(det.dialect, Dialect::Bash);
    assert_eq!(det.family, Family::NodeBashObfuscate);
    assert!(det.confidence >= 0.7, "confidence={}", det.confidence);
}

#[test]
fn clean_script_is_not_misdetected() {
    let clean: String = read_corpus("bash/node-bash-obfuscate/clean_original.sh");
    assert!(!is_node_bash_obfuscate(&clean));
    let det: Detection = detect(clean.as_bytes());
    assert_ne!(det.family, Family::NodeBashObfuscate);
}

#[test]
fn recovery_matches_original_behavior_under_bash() {
    let bash: String = bash_path().unwrap_or_else(|reason: String| {
        panic!(
            "bash is required for the non-circular exec-diff grading: {reason}; set \
             {BASH_BIN_VAR} or put bash on PATH"
        )
    });
    for (obf_rel, label) in [
        ("bash/node-bash-obfuscate/obfuscated_chunk4.sh", "chunk4"),
        ("bash/node-bash-obfuscate/obfuscated_chunk8.sh", "chunk8"),
    ] {
        let original: String = read_corpus("bash/node-bash-obfuscate/clean_original.sh");
        let obf: String = read_corpus(obf_rel);
        let report: NodeBashObfuscateReport =
            reverse_node_bash_obfuscate(&obf).expect("recovery present");
        assert!(
            report.walls.is_empty(),
            "[{label}] walls={:?}",
            report.walls
        );
        assert_exec_equivalent(&bash, &original, &report.output, label);
    }
}

#[test]
fn recovery_matches_original_behavior_under_dash() {
    let dash: String = dash_path().unwrap_or_else(|reason: String| {
        panic!(
            "dash is required for the non-circular exec-diff grading: {reason}; set \
             {DASH_BIN_VAR} or put dash on PATH"
        )
    });
    let original: String = read_corpus("bash/node-bash-obfuscate/clean_original.sh");
    let obf: String = read_corpus("bash/node-bash-obfuscate/obfuscated_chunk4.sh");
    let report: NodeBashObfuscateReport =
        reverse_node_bash_obfuscate(&obf).expect("recovery present");
    assert_exec_equivalent(&dash, &original, &report.output, "dash-chunk4");
}

#[test]
fn recovered_script_is_plaintext_not_eval_wrapped() {
    let obf: String = read_corpus("bash/node-bash-obfuscate/obfuscated_chunk4.sh");
    let report: NodeBashObfuscateReport =
        reverse_node_bash_obfuscate(&obf).expect("recovery present");
    assert!(
        !report.output.contains("eval \"$"),
        "recovery must peel the eval chunk-table, not leave it intact; out={}",
        report.output
    );
    assert!(report.output.contains("GREETING='hello world'"));
    assert!(report.output.contains("for i in 1 2 3; do"));
}
