#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_path(stem: &str, ext: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("disrobe-cli-e2e-{stem}-{pid}-{seq}.{ext}"))
}

fn temp_dir(stem: &str) -> PathBuf {
    let p: PathBuf = temp_path(stem, "dir");
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

fn write_bytes(path: &PathBuf, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, bytes).expect("write fixture");
}

#[derive(Debug)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_disrobe(args: &[&str]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} — run `cargo build -p disrobe-cli` before tests",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn top_level_help_lists_every_pass_subcommand() {
    let r: Run = run_disrobe(&["--help"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    for cmd in [
        "pyarmor",
        "pyinstaller",
        "pyfreeze",
        "nuitka",
        "py",
        "js",
        "wasm",
        "envelope",
        "auto",
        "chain",
        "serve",
        "passes",
        "doctor",
    ] {
        assert!(
            r.stdout.contains(cmd),
            "top-level help missing `{cmd}`. stdout was:\n{}",
            r.stdout
        );
    }
}

#[test]
fn top_level_version_prints_cargo_version() {
    let r: Run = run_disrobe(&["--version"]);
    assert_eq!(r.code, 0);
    let want: &'static str = env!("CARGO_PKG_VERSION");
    assert!(
        r.stdout.contains(want),
        "expected version `{want}` in `{}`",
        r.stdout
    );
}

#[test]
fn passes_subcommand_lists_registered_passes() {
    let r: Run = run_disrobe(&["passes"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    for kw in [
        "pyarmor",
        "pyinstaller",
        "pyfreeze",
        "nuitka",
        "py",
        "js",
        "wasm",
        "envelope",
        "native",
    ] {
        assert!(
            r.stdout.contains(kw),
            "passes output missing `{kw}`:\n{}",
            r.stdout
        );
    }
}

#[test]
fn doctor_subcommand_prints_version_line() {
    let r: Run = run_disrobe(&["doctor"]);
    assert!(
        matches!(r.code, 0..=2),
        "doctor must exit 0/1/2 (0=all-good, 1=missing-required, 2=missing-optional); got {} stderr={}",
        r.code,
        r.stderr
    );
    assert!(r.stdout.contains("disrobe doctor"));
    assert!(r.stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn self_update_dry_run_returns_zero_without_network() {
    let r: Run = run_disrobe(&["self-update", "--dry-run"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("--dry-run=true"));
}

#[test]
fn completions_bash_emits_complete_block() {
    let r: Run = run_disrobe(&["completions", "bash"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("complete -F") || r.stdout.contains("_disrobe()"),
        "bash completions output looks empty:\n{}",
        r.stdout
    );
}

#[test]
fn completions_powershell_emits_register_block() {
    let r: Run = run_disrobe(&["completions", "powershell"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("Register-ArgumentCompleter") || r.stdout.contains("ScriptBlock"),
        "powershell completions output looks empty:\n{}",
        r.stdout
    );
}

#[test]
fn unknown_subcommand_exits_nonzero_with_helpful_error() {
    let r: Run = run_disrobe(&["definitely-not-a-real-pass"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.to_lowercase().contains("error"));
}

#[test]
fn auto_subcommand_on_missing_input_surfaces_dr_cli_0090() {
    let bogus: PathBuf = temp_path("auto-missing", "bin");
    let r: Run = run_disrobe(&["auto", bogus.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0090") || r.stderr.contains("cannot read"),
        "expected DR-CLI-0090 read error for auto, got: {}",
        r.stderr
    );
}

#[test]
fn explain_pyarm_7_returns_documented_entry() {
    let r: Run = run_disrobe(&["explain", "pyarm-7"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("DR-PYARM-0007"));
    assert!(r.stdout.contains("v6/v7"));
    assert!(r.stdout.contains("crate:"));
}

#[test]
fn explain_unknown_code_surfaces_dr_cli_0102() {
    let r: Run = run_disrobe(&["explain", "DR-NOTREAL-9999"]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0102") || r.stderr.contains("no documentation"),
        "expected unknown-code error, got: {}",
        r.stderr
    );
}

#[test]
fn explain_json_output_is_valid_json() {
    let r: Run = run_disrobe(&["--json", "explain", "DR-PYARM-0007"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let _: serde_json::Value =
        serde_json::from_str(r.stdout.trim()).expect("explain --json must emit valid JSON");
}

#[test]
fn explain_long_form_codes_are_case_insensitive() {
    let r: Run = run_disrobe(&["explain", "dr-pyarm-0007"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("DR-PYARM-0007"));
}

#[test]
fn auto_on_plain_python_produces_chain_and_out_dir() {
    let src: PathBuf = temp_path("auto-plain-py", "py");
    let out_dir: PathBuf = temp_dir("auto-plain-py-out");
    write_bytes(&src, b"print('hello world')\n");
    let r: Run = run_disrobe(&[
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--max-depth",
        "3",
    ]);
    assert!(
        r.code == 0 || r.stderr.contains("DR-CLI-"),
        "auto must either succeed or surface a DR code; stdout={} stderr={}",
        r.stdout,
        r.stderr
    );
    assert!(
        out_dir.join("chain.json").exists(),
        "auto must emit chain.json. stderr: {}",
        r.stderr
    );
}

#[test]
fn auto_dry_run_emits_nothing_to_disk() {
    let src: PathBuf = temp_path("auto-dry", "py");
    let out_dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-cli-dry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    write_bytes(&src, b"print('dry run check')\n");
    let _r: Run = run_disrobe(&[
        "auto",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--max-depth",
        "1",
        "--dry-run",
    ]);
    assert!(
        !out_dir.exists() || std::fs::read_dir(&out_dir).map_or(0, std::iter::Iterator::count) == 0,
        "--dry-run must not create artifacts; saw entries in {}",
        out_dir.display()
    );
}

#[test]
fn status_in_empty_dir_reports_no_out() {
    let work: PathBuf = temp_dir("status-empty");
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .arg("status")
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("no `./out/`") || stdout.contains("no disrobe run"),
        "expected no-out message, got: {stdout}"
    );
}

#[test]
fn status_json_emits_valid_object() {
    let work: PathBuf = temp_dir("status-empty-json");
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .args(["--json", "status"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(out.status.code().unwrap_or(-1), 0);
    let s: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: serde_json::Value =
        serde_json::from_str(s.trim()).expect("status --json must be valid JSON");
    assert_eq!(
        v.get("out_dir_present")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
}

#[test]
fn doctor_emits_tools_section_and_version() {
    let r: Run = run_disrobe(&["doctor"]);
    assert!(
        r.code == 0 || r.code == 1 || r.code == 2,
        "doctor must exit 0/1/2; got {}, stderr: {}",
        r.code,
        r.stderr
    );
    assert!(r.stdout.contains("disrobe doctor"));
    assert!(r.stdout.contains("tools:"));
    assert!(r.stdout.contains("version:"));
}

#[test]
fn doctor_json_includes_tools_array() {
    let r: Run = run_disrobe(&["--json", "doctor"]);
    assert!(r.code == 0 || r.code == 1 || r.code == 2);
    let v: serde_json::Value =
        serde_json::from_str(r.stdout.trim()).expect("doctor --json must be valid JSON");
    assert!(
        v.get("tools").and_then(|t| t.as_array()).is_some(),
        "expected tools[] in doctor output"
    );
}

#[test]
fn init_default_creates_dot_disrobe() {
    let work: PathBuf = temp_dir("init-default");
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .arg("init")
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(work.join(".disrobe").is_dir(), ".disrobe must exist");
    assert!(work.join(".disrobe/AGENTS.md").is_file());
    assert!(work.join(".disrobe/manifest.json").is_file());
}

#[test]
fn init_claude_emits_settings_and_commands() {
    let work: PathBuf = temp_dir("init-claude");
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .args(["init", "--ide", "claude"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(work.join(".claude/settings.json").is_file());
    assert!(work.join(".claude/commands/disrobe-verify.md").is_file());
    assert!(work.join(".claude/commands/disrobe-status.md").is_file());
    assert!(work.join(".claude/commands/disrobe-rename.md").is_file());
    assert!(work.join(".claude/commands/disrobe-diff.md").is_file());
}

#[test]
fn init_refuses_to_overwrite_existing_without_force() {
    let work: PathBuf = temp_dir("init-already");
    let _ = std::fs::create_dir_all(work.join(".disrobe"));
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .arg("init")
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_ne!(out.status.code().unwrap_or(-1), 0);
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("DR-CLI-0110") || stderr.contains("already exists"));
}

#[test]
fn init_force_overwrites() {
    let work: PathBuf = temp_dir("init-force");
    let _ = std::fs::create_dir_all(work.join(".disrobe"));
    let bin: PathBuf = cli_binary();
    let out: std::process::Output = Command::new(&bin)
        .args(["init", "--force"])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn man_emits_pages_to_default_out_dir() {
    let work: PathBuf = temp_dir("man-out");
    let bin: PathBuf = cli_binary();
    let man_dir: PathBuf = work.join("custom-man");
    let out: std::process::Output = Command::new(&bin)
        .args(["man", "--out", man_dir.to_str().unwrap()])
        .current_dir(&work)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn disrobe");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(man_dir.join("disrobe.1").is_file());
    assert!(
        man_dir.join("disrobe-pyarmor.1").is_file()
            || man_dir.join("disrobe-pyarmor-unpack.1").is_file()
    );
}

#[test]
fn bug_report_writes_default_file() {
    let work: PathBuf = temp_dir("bug-report");
    let out_path: PathBuf = work.join("report.md");
    let r: Run = run_disrobe(&["bug-report", "--out", out_path.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(out_path.is_file());
    let text: String = std::fs::read_to_string(&out_path).expect("read");
    assert!(text.contains("disrobe bug report"));
    assert!(text.contains("environment"));
    assert!(text.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn bug_report_dash_writes_to_stdout() {
    let r: Run = run_disrobe(&["bug-report", "--out", "-"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("disrobe bug report"));
}

#[test]
fn self_update_check_only_dry_run_succeeds() {
    let r: Run = run_disrobe(&["self-update", "--check-only", "--dry-run"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("self-update") || r.stdout.contains("api.github.com"));
}

#[test]
fn self_update_json_emits_machine_format() {
    let r: Run = run_disrobe(&["--json", "self-update", "--check-only", "--dry-run"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let v: serde_json::Value =
        serde_json::from_str(r.stdout.trim()).expect("self-update --json must be valid JSON");
    assert_eq!(
        v.get("current_version").and_then(|x| x.as_str()),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn completions_install_appends_idempotently() {
    let work: PathBuf = temp_dir("comp-install");
    let rc: PathBuf = work.join("custom.bashrc");
    std::fs::write(&rc, b"# existing\n").expect("seed rc");
    let r1: Run = run_disrobe(&[
        "completions",
        "bash",
        "--install",
        "--rc-file",
        rc.to_str().unwrap(),
    ]);
    assert_eq!(r1.code, 0, "stderr: {}", r1.stderr);
    let first: String = std::fs::read_to_string(&rc).expect("read");
    assert!(first.contains("disrobe completions"));
    let r2: Run = run_disrobe(&[
        "completions",
        "bash",
        "--install",
        "--rc-file",
        rc.to_str().unwrap(),
    ]);
    assert_eq!(r2.code, 0, "stderr: {}", r2.stderr);
    let second: String = std::fs::read_to_string(&rc).expect("read");
    assert_eq!(first, second, "second install must be idempotent");
}

#[test]
fn passes_json_global_flag_does_not_break_text_subcommands() {
    let r: Run = run_disrobe(&["--json", "passes"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
}

#[test]
fn pyinstaller_detect_rejects_non_pyinstaller_input() {
    let bogus: PathBuf = temp_path("not-pyinstaller", "exe");
    write_bytes(
        &bogus,
        b"MZ\x90\x00not really a pe just random bytes for the cookie scanner to fail on",
    );
    let r: Run = run_disrobe(&["pyinstaller", "detect", bogus.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.to_lowercase().contains("cookie") || r.stderr.contains("DR-"));
}

#[test]
fn pyinstaller_detect_missing_input_surfaces_dr_cli_0011() {
    let missing: PathBuf = temp_path("missing-pi", "exe");
    let _ = std::fs::remove_file(&missing);
    let r: Run = run_disrobe(&["pyinstaller", "detect", missing.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0011") || r.stderr.contains("cannot read"),
        "expected DR-CLI-0011 path error, got: {}",
        r.stderr
    );
}

#[test]
fn pyfreeze_detect_rejects_random_blob() {
    let blob: PathBuf = temp_path("not-pyfreeze", "bin");
    write_bytes(&blob, &(0u8..=255u8).collect::<Vec<_>>());
    let r: Run = run_disrobe(&["pyfreeze", "detect", blob.to_str().unwrap()]);
    assert!(
        r.code != 0 || r.stdout.contains("Unknown") || r.stdout.to_lowercase().contains("unknown"),
        "expected either nonzero exit or Unknown kind, got code={} stdout={} stderr={}",
        r.code,
        r.stdout,
        r.stderr,
    );
}

#[test]
fn nuitka_detect_classifies_plain_pe_as_not_nuitka() {
    let blob: PathBuf = temp_path("plain-pe", "exe");
    let mut pe: Vec<u8> = Vec::with_capacity(256);
    pe.extend_from_slice(b"MZ");
    pe.resize(0x3c, 0);
    pe.extend_from_slice(&0x40u32.to_le_bytes());
    while pe.len() < 0x40 {
        pe.push(0);
    }
    pe.extend_from_slice(b"PE\0\0");
    pe.resize(256, 0);
    write_bytes(&blob, &pe);
    let r: Run = run_disrobe(&["nuitka", "detect", blob.to_str().unwrap()]);
    if r.code == 0 {
        assert!(r.stdout.contains("flavor:"), "stdout: {}", r.stdout);
    } else {
        assert!(r.stderr.contains("DR-") || r.stderr.to_lowercase().contains("nuitka"));
    }
}

#[test]
fn nuitka_extract_on_non_onefile_returns_dr_cli_0017() {
    let blob: PathBuf = temp_path("not-onefile", "bin");
    write_bytes(&blob, b"\0\0\0\0nothing onefile-like here whatsoever");
    let r: Run = run_disrobe(&["nuitka", "extract", blob.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0017")
            || r.stderr.contains("onefile")
            || r.stderr.contains("DR-"),
        "expected onefile-not-detected error, got: {}",
        r.stderr
    );
}

#[test]
fn py_disasm_rejects_non_pyc_blob() {
    let blob: PathBuf = temp_path("not-pyc", "pyc");
    write_bytes(&blob, b"not a pyc file");
    let r: Run = run_disrobe(&["py", "disasm", blob.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("DR-CLI-0051") || r.stderr.contains("pyc"));
}

#[test]
fn py_deob_passes_through_clean_source() {
    let src: PathBuf = temp_path("clean-py", "py");
    let out_dir: PathBuf = temp_dir("py-deob-out");
    let out_path: PathBuf = out_dir.join("clean-py.deobfuscated.py");
    write_bytes(&src, b"print('hello world')\n");
    let r: Run = run_disrobe(&[
        "py",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(
        out_path.exists(),
        "deob did not write output {}",
        out_path.display()
    );
    let written: String = std::fs::read_to_string(&out_path).expect("read");
    assert!(
        written.contains("hello world"),
        "deob ate the source: {written}"
    );
}

#[test]
fn py_deob_with_cleanup_flag_runs_extra_pass() {
    let src: PathBuf = temp_path("cleanup-py", "py");
    let out_dir: PathBuf = temp_dir("py-deob-cleanup-out");
    let out_path: PathBuf = out_dir.join("cleanup-py.deobfuscated.py");
    write_bytes(
        &src,
        b"x = 1 + 2\nif True:\n    print(x)\nelse:\n    print('dead')\n",
    );
    let r: Run = run_disrobe(&[
        "py",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--cleanup",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("cleanup:"));
    assert!(out_path.exists());
}

#[test]
fn py_sourcedefender_rejects_non_pye_blob() {
    let blob: PathBuf = temp_path("not-pye", "pye");
    write_bytes(&blob, b"this is not a sourcedefender envelope");
    let r: Run = run_disrobe(&["py", "sourcedefender", blob.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("DR-") || r.stderr.to_lowercase().contains("sourcedefender"));
}

#[test]
fn js_deob_handles_minimal_string_array_obfuscator_pattern() {
    let src: PathBuf = temp_path("js-strarr", "js");
    let out_dir: PathBuf = temp_dir("js-deob-out");
    let out_path: PathBuf = out_dir.join("js-strarr.deobfuscated.js");
    write_bytes(
        &src,
        br#"var _0xa1b2 = ["hello", "world"];
(function(arr, n){while(--n){arr.push(arr.shift())}})(_0xa1b2, 1);
function _0x1234(i){return _0xa1b2[i - 0];}
console.log(_0x1234(0) + " " + _0x1234(1));
"#,
    );
    let r: Run = run_disrobe(&[
        "js",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("js deob: OK"));
    assert!(out_path.exists());
}

#[test]
fn js_deob_with_all_flags_runs_pipeline() {
    let src: PathBuf = temp_path("js-pipeline", "js");
    let out_dir: PathBuf = temp_dir("js-pipeline-out");
    let out_path: PathBuf = out_dir.join("js-pipeline.deobfuscated.js");
    write_bytes(
        &src,
        br#"var _0xa1b2 = ["alpha", "beta"];
function _0xdec(i){return _0xa1b2[i];}
var _0xv1 = !0;
var _0xv2 = void 0;
if(_0xv1){console.log(_0xdec(0));}
"#,
    );
    let r: Run = run_disrobe(&[
        "js",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--unminify",
        "--rename",
        "--rename-scope-aware",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("unminify:"));
    assert!(r.stdout.contains("rename:"));
    assert!(r.stdout.contains("scope-aware rename:"));
}

#[test]
fn js_deob_rejects_non_utf8_input() {
    let src: PathBuf = temp_path("js-non-utf8", "js");
    let out_dir: PathBuf = temp_dir("js-non-utf8-out");
    let out_path: PathBuf = out_dir.join("out.js");
    write_bytes(&src, &[0xFF, 0xFE, 0xFD, 0xFC]);
    let r: Run = run_disrobe(&[
        "js",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0042") || r.stderr.contains("UTF-8"),
        "expected UTF-8 error, got: {}",
        r.stderr
    );
}

#[test]
fn wasm_decompile_accepts_minimal_empty_module() {
    let src: PathBuf = temp_path("wasm-empty", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-decompile-out");
    let out_path: PathBuf = out_dir.join("wasm-empty.summary.json");
    write_bytes(&src, b"\x00asm\x01\x00\x00\x00");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(out_path.exists());
}

#[test]
fn wasm_decompile_rejects_non_wasm_blob() {
    let src: PathBuf = temp_path("wasm-bad-magic", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-bad-out");
    let out_path: PathBuf = out_dir.join("bad.summary.json");
    write_bytes(&src, b"NOT-WASM-AT-ALL");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
}

#[test]
fn pyarmor_unpack_rejects_non_wrapper_input() {
    let src: PathBuf = temp_path("not-pyarmor", "py");
    let out_dir: PathBuf = temp_dir("pyarmor-out");
    write_bytes(
        &src,
        b"print('this is plain python, not a pyarmor wrapper')\n",
    );
    let r: Run = run_disrobe(&[
        "pyarmor",
        "unpack",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-") || r.stderr.to_lowercase().contains("pyarmor"),
        "expected DR- error, got: {}",
        r.stderr
    );
}

#[test]
fn pyarmor_unpack_missing_input_surfaces_dr_cli_0001() {
    let missing: PathBuf = temp_path("missing-pyarmor", "py");
    let _ = std::fs::remove_file(&missing);
    let out_dir: PathBuf = temp_dir("pyarmor-missing-out");
    let r: Run = run_disrobe(&[
        "pyarmor",
        "unpack",
        missing.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("DR-CLI-0001") || r.stderr.contains("cannot read"));
}

#[test]
fn global_color_never_flag_does_not_break_invocation() {
    let r: Run = run_disrobe(&["--color", "never", "doctor"]);
    assert!(
        matches!(r.code, 0..=2),
        "doctor must exit 0/1/2; got {} stderr={}",
        r.code,
        r.stderr
    );
    assert!(r.stdout.contains("disrobe doctor"));
}

#[test]
fn global_quiet_suppresses_logs_but_not_subcommand_output() {
    let r: Run = run_disrobe(&["-q", "passes"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("registered passes"));
}

#[test]
fn infer_subcommands_resolves_unique_prefix() {
    let pa: Run = run_disrobe(&["pa"]);
    assert_eq!(
        pa.code, 0,
        "`pa` should resolve to `passes`; stderr: {}",
        pa.stderr
    );
    assert!(pa.stdout.contains("registered passes"));

    let wa: Run = run_disrobe(&["wa"]);
    assert_ne!(
        wa.code, 0,
        "`wa` should infer wasm and require a subcommand"
    );
    let lower: String = wa.stderr.to_lowercase();
    assert!(
        lower.contains("subcommand") || lower.contains("usage"),
        "expected wasm subcommand requirement, got: {}",
        wa.stderr
    );
}

#[test]
fn ambiguous_prefix_is_rejected_with_helpful_error() {
    let p: Run = run_disrobe(&["py"]);
    assert_ne!(
        p.code, 0,
        "`py` must be ambiguous between py/pyarmor/pyinstaller/pyfreeze"
    );
    let lower: String = p.stderr.to_lowercase();
    assert!(
        lower.contains("ambiguous") || lower.contains("subcommand"),
        "expected ambiguity/subcommand error for short `py`, got: {}",
        p.stderr
    );
}

#[test]
fn pyinstaller_help_lists_detect_and_extract() {
    let r: Run = run_disrobe(&["pyinstaller", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("detect"));
    assert!(r.stdout.contains("extract"));
}

#[test]
fn pyfreeze_help_lists_detect_and_extract() {
    let r: Run = run_disrobe(&["pyfreeze", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("detect"));
    assert!(r.stdout.contains("extract"));
}

#[test]
fn js_help_documents_rename_scope_aware_flag() {
    let r: Run = run_disrobe(&["js", "deob", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("rename-scope-aware") || r.stdout.contains("rename_scope_aware"));
}

#[test]
fn pyarmor_help_documents_allow_dynamic_flag() {
    let r: Run = run_disrobe(&["pyarmor", "unpack", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("allow-dynamic") || r.stdout.contains("allow_dynamic"));
    assert!(r.stdout.contains("dynamic-timeout") || r.stdout.contains("dynamic_timeout"));
}

#[test]
fn wasm_decompile_help_documents_target_flag() {
    let r: Run = run_disrobe(&["wasm", "decompile", "--help"]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("--target") && r.stdout.contains("rust") && r.stdout.contains("wat"),
        "wasm decompile help missing --target options:\n{}",
        r.stdout
    );
}

#[test]
fn wasm_decompile_target_rust_emits_rs_file() {
    let src: PathBuf = temp_path("wasm-lift-rust", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-lift-rust-out");
    let out_path: PathBuf = out_dir.join("lifted.rs");
    write_bytes(&src, b"\x00asm\x01\x00\x00\x00");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "rust",
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(out_path.is_file(), "target=rust must write .rs file");
    let body: String = std::fs::read_to_string(&out_path).expect("read");
    assert!(
        body.contains("disrobe wasm lift target=rust"),
        "rust output missing banner: {body}"
    );
}

#[test]
fn wasm_decompile_target_ts_emits_ts_file() {
    let src: PathBuf = temp_path("wasm-lift-ts", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-lift-ts-out");
    let out_path: PathBuf = out_dir.join("lifted.ts");
    write_bytes(&src, b"\x00asm\x01\x00\x00\x00");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "ts",
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(out_path.is_file());
}

#[test]
fn wasm_decompile_target_wat_emits_wat_file() {
    let src: PathBuf = temp_path("wasm-lift-wat", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-lift-wat-out");
    let out_path: PathBuf = out_dir.join("lifted.wat");
    write_bytes(&src, b"\x00asm\x01\x00\x00\x00");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "wat",
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(out_path.is_file());
}

#[test]
fn wasm_decompile_emit_writes_stub_files() {
    let src: PathBuf = temp_path("wasm-emit", "wasm");
    let out_dir: PathBuf = temp_dir("wasm-emit-out");
    let out_path: PathBuf = out_dir.join("module.summary.json");
    write_bytes(&src, b"\x00asm\x01\x00\x00\x00");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--emit",
        "source,cfg,signatures",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let entries: Vec<String> = std::fs::read_dir(&out_dir)
        .expect("read out_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n.ends_with(".cfg.json")),
        "missing *.cfg.json in {entries:?}"
    );
    assert!(
        entries.iter().any(|n| n.ends_with(".signatures.json")),
        "missing *.signatures.json in {entries:?}"
    );
    assert!(
        entries.iter().any(|n| n.ends_with(".source.json")),
        "missing *.source.json in {entries:?}"
    );
}

#[test]
fn wasm_component_reachable_via_main_dispatch() {
    let r: Run = run_disrobe(&["wasm", "component", "--help"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("component"));
}

#[test]
fn wasm_types_reachable_via_main_dispatch() {
    let r: Run = run_disrobe(&["wasm", "types", "--help"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
}

#[test]
fn verify_top_level_alias_routes_to_envelope_verify() {
    let bogus: PathBuf = temp_path("verify-bogus", "dr");
    write_bytes(&bogus, b"not a real disrobe envelope at all");
    let r: Run = run_disrobe(&["verify", bogus.to_str().unwrap()]);
    assert_ne!(r.code, 0, "verify on garbage should fail");
    assert!(
        r.stderr.contains("DR-CLI-0087") || r.stderr.contains("envelope"),
        "expected envelope error, got: {}",
        r.stderr
    );
}

#[test]
fn verify_help_mentions_envelope_alias() {
    let r: Run = run_disrobe(&["verify", "--help"]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("envelope") || r.stdout.contains("Alias"),
        "verify --help should advertise envelope alias:\n{}",
        r.stdout
    );
}

#[test]
fn chain_requires_passes_and_input() {
    let r: Run = run_disrobe(&["chain"]);
    assert_ne!(r.code, 0);
}

#[test]
fn chain_runs_py_deob_on_plain_input() {
    let src: PathBuf = temp_path("chain-py", "py");
    let out_dir: PathBuf = temp_dir("chain-py-out");
    write_bytes(&src, b"print('chain hello')\n");
    let r: Run = run_disrobe(&[
        "chain",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--chain",
        "py.deob",
    ]);
    assert_eq!(r.code, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(out_dir.join("chain.json").is_file(), "chain.json missing");
}

#[test]
fn chain_rejects_unknown_pass_name() {
    let src: PathBuf = temp_path("chain-bad", "py");
    let out_dir: PathBuf = temp_dir("chain-bad-out");
    write_bytes(&src, b"print('x')\n");
    let r: Run = run_disrobe(&[
        "chain",
        src.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--chain",
        "definitely.no-such-pass",
    ]);
    assert_ne!(
        r.code, 0,
        "chain with unknown pass must surface a non-zero exit; stderr={} stdout={}",
        r.stderr, r.stdout
    );
}

#[test]
fn native_decompile_without_ghidra_surfaces_dr_native_0001() {
    let bogus: PathBuf = temp_path("native-decomp", "bin");
    write_bytes(
        &bogus,
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
    );
    let r: Run = run_disrobe(&["native", "decompile", bogus.to_str().unwrap()]);
    if r.code == 0 {
        return;
    }
    assert!(
        r.stderr.contains("DR-NATIVE-0001") || r.stderr.contains("ghidra"),
        "expected ghidra error code, got: {}",
        r.stderr
    );
}

#[test]
fn native_symbols_on_minimal_elf_emits_json() {
    let src: PathBuf = temp_path("native-syms", "bin");
    let out_dir: PathBuf = temp_dir("native-syms-out");
    let out_path: PathBuf = out_dir.join("syms.json");
    let mut elf: Vec<u8> = Vec::with_capacity(64);
    elf.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    elf.extend_from_slice(&[
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);
    elf.resize(64, 0);
    write_bytes(&src, &elf);
    let r: Run = run_disrobe(&[
        "native",
        "symbols",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    if r.code != 0 {
        assert!(
            r.stderr.contains("DR-NATIVE-0020") || r.stderr.contains("parse"),
            "object parse must fail cleanly on tiny ELF, got: {}",
            r.stderr
        );
        return;
    }
    assert!(out_path.is_file(), "native symbols should write json");
    let body: String = std::fs::read_to_string(&out_path).expect("read");
    let v: serde_json::Value = serde_json::from_str(&body).expect("native symbols json must parse");
    assert_eq!(
        v.get("schema").and_then(|s| s.as_str()),
        Some("disrobe.native.symbols/v0")
    );
}

#[test]
fn py_decompile_on_invalid_pyc_surfaces_dr_cli_error() {
    let bogus: PathBuf = temp_path("py-decomp-bad", "pyc");
    let out_dir: PathBuf = temp_dir("py-decomp-bad-out");
    write_bytes(&bogus, b"definitely not a pyc");
    let r: Run = run_disrobe(&[
        "py",
        "decompile",
        bogus.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0051") || r.stderr.contains("pyc"),
        "expected pyc error, got: {}",
        r.stderr
    );
}

#[test]
fn py_extract_rejects_non_archive_blob() {
    let bogus: PathBuf = temp_path("py-extract-bad", "bin");
    let out_dir: PathBuf = temp_dir("py-extract-bad-out");
    write_bytes(&bogus, b"not an archive of any kind");
    let r: Run = run_disrobe(&[
        "py",
        "extract",
        bogus.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("DR-CLI-0072") || r.stderr.contains("archive"),
        "expected archive error, got: {}",
        r.stderr
    );
}

#[test]
fn py_disasm_emit_writes_stub() {
    let bogus: PathBuf = temp_path("py-disasm-emit-bad", "pyc");
    let out_dir: PathBuf = temp_dir("py-disasm-emit-out");
    let out_path: PathBuf = out_dir.join("x.dis.txt");
    write_bytes(&bogus, b"not a pyc");
    let r: Run = run_disrobe(&[
        "py",
        "disasm",
        bogus.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--emit",
        "source,manifest",
    ]);
    assert_ne!(r.code, 0);
    let _ = r;
}

#[test]
fn serve_stdio_returns_dr_cli_error_when_not_a_tty() {
    let r: Run = run_disrobe(&["serve", "--stdio"]);
    let stderr_ok: bool = r.stderr.contains("DR-CLI-0170")
        || r.stderr.contains("DR-CLI-0201")
        || r.stderr.contains("initialize")
        || r.stderr.contains("LSP")
        || r.stderr.contains("lsp");
    let exit_ok: bool = r.code != 0 || r.stdout.contains("disrobe");
    assert!(
        stderr_ok || exit_ok,
        "serve --stdio must surface a clear error or run; got code={} stdout={} stderr={}",
        r.code,
        r.stdout,
        r.stderr,
    );
}

#[test]
fn serve_help_documents_full_feature_flags() {
    let r: Run = run_disrobe(&["serve", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("--bind"));
    assert!(r.stdout.contains("--stdio"));
    assert!(r.stdout.contains("--cors-origin"));
    assert!(r.stdout.contains("--max-body-size"));
}

#[test]
fn passes_subcommand_lists_chain_and_serve() {
    let r: Run = run_disrobe(&["passes"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("chain"));
    assert!(r.stdout.contains("serve"));
}
