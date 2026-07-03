#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_shell::{
    Detection, Dialect, Family, NodeBashObfuscateReport, detect, is_node_bash_obfuscate,
    reverse_node_bash_obfuscate,
};

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

fn shell_path(names: &[&str], absolute: &[&str]) -> Option<String> {
    for candidate in absolute {
        if std::path::Path::new(candidate).exists() {
            return Some((*candidate).to_owned());
        }
    }
    for name in names {
        let probe: std::io::Result<std::process::Output> =
            Command::new(name).arg("--version").output();
        if probe.is_ok_and(|o: std::process::Output| o.status.success()) {
            return Some((*name).to_owned());
        }
        let probe_c: std::io::Result<std::process::Output> =
            Command::new(name).arg("-c").arg("exit 0").output();
        if probe_c.is_ok_and(|o: std::process::Output| o.status.success()) {
            return Some((*name).to_owned());
        }
    }
    None
}

fn bash_path() -> Option<String> {
    shell_path(
        &["bash"],
        &[
            "/usr/bin/bash",
            "/bin/bash",
            "C:/Program Files/Git/usr/bin/bash.exe",
            "C:/cygwin64/bin/bash.exe",
        ],
    )
}

fn dash_path() -> Option<String> {
    shell_path(
        &["dash"],
        &["/usr/bin/dash", "/bin/dash", "C:/cygwin64/bin/dash.exe"],
    )
}

struct Observed {
    stdout: Vec<u8>,
    code: Option<i32>,
}

fn run_script(shell: &str, script: &str) -> Observed {
    let out: std::process::Output = Command::new(shell)
        .arg("-c")
        .arg(script)
        .output()
        .expect("spawn sandboxed shell");
    Observed {
        stdout: out.stdout,
        code: out.status.code(),
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
    let Some(bash): Option<String> = bash_path() else {
        eprintln!("skip: no on-box bash for non-circular exec-diff grading");
        return;
    };
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
    let Some(dash): Option<String> = dash_path() else {
        eprintln!("skip: no on-box dash for non-circular exec-diff grading");
        return;
    };
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
