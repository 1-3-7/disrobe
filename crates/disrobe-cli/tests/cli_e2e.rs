#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::Command;

#[cfg(feature = "dotnet")]
use disrobe_pass_dotnet::iterator_reverse::is_unlowered_compiler_construct_refusal;
use zip::write::{FileOptions, ZipWriter};

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

fn temp_path(stem: &str, ext: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-cli-e2e-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let path: PathBuf = scratch.path().join(format!("payload.{ext}"));
    (scratch, path)
}

fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-cli-e2e-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(root.pop(), "crate manifest directory must have a parent");
    assert!(root.pop(), "crates directory must have a parent");
    root
}

fn ipa_with_swift_hello() -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let fixture: PathBuf = workspace_root()
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
        .join("SwiftHello.original");
    let original: Vec<u8> = std::fs::read(&fixture).expect("read committed SwiftHello Mach-O");
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(original.len() + 1024));
    let mut archive: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(cursor);
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    archive
        .start_file("Payload/SwiftHello.app/Info.plist", options)
        .expect("start Info.plist entry");
    archive
        .write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>SwiftHello</string></dict></plist>"#,
        )
        .expect("write Info.plist entry");
    archive
        .start_file("Payload/SwiftHello.app/SwiftHello", options)
        .expect("start Mach-O entry");
    archive.write_all(&original).expect("write Mach-O entry");
    let ipa_bytes: Vec<u8> = archive.finish().expect("finish IPA archive").into_inner();
    let (scratch, ipa_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("swift-ipa-boundary", "ipa");
    write_bytes(&ipa_path, &ipa_bytes);
    (scratch, ipa_path)
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
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` before tests",
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
fn ipa_is_limited_to_macho_dump_not_classdump() {
    let (scratch, ipa_path): (disrobe_core::scratch::ScratchDir, PathBuf) = ipa_with_swift_hello();
    let ipa: &str = ipa_path.to_str().expect("IPA path must be valid UTF-8");

    let swift: Run = run_disrobe(&["swift", "classdump", ipa]);
    assert_ne!(
        swift.code, 0,
        "swift classdump unexpectedly accepted an IPA"
    );
    assert!(
        swift.stderr.contains("DR-CLI-0701"),
        "swift classdump must refuse IPA archive bytes: {}",
        swift.stderr
    );

    let classdump_out: PathBuf = scratch.path().join("classdump-out");
    let classdump_out_text: &str = classdump_out
        .to_str()
        .expect("classdump output path must be valid UTF-8");
    let classdump: Run = run_disrobe(&["macho", "classdump", ipa, "--out", classdump_out_text]);
    assert_ne!(
        classdump.code, 0,
        "macho classdump unexpectedly accepted an IPA"
    );
    assert!(
        classdump.stderr.contains("DR-CLI-0510"),
        "macho classdump must refuse IPA archive bytes: {}",
        classdump.stderr
    );

    let dump_path: PathBuf = scratch.path().join("macho-dump.json");
    let dump_path_text: &str = dump_path.to_str().expect("dump path must be valid UTF-8");
    let dump: Run = run_disrobe(&["macho", "dump", ipa, "--out", dump_path_text]);
    assert_eq!(
        dump.code, 0,
        "macho dump rejected a valid IPA: {}",
        dump.stderr
    );
    let report_raw: String = std::fs::read_to_string(&dump_path).expect("read Mach-O dump JSON");
    let report: serde_json::Value =
        serde_json::from_str(&report_raw).expect("parse Mach-O dump JSON");
    assert_eq!(
        report["container"],
        serde_json::Value::String("Ipa".to_owned()),
        "macho dump must report the IPA container"
    );
}

#[test]
fn swift_and_macho_help_distinguish_ipa_and_mapping_parsing() {
    let swift_help: Run = run_disrobe(&["swift", "classdump", "--help"]);
    assert_eq!(swift_help.code, 0, "stderr: {}", swift_help.stderr);
    assert!(swift_help.stdout.contains("thin Mach-O"));
    assert!(
        !swift_help.stdout.contains(".ipa"),
        "swift classdump help must not advertise IPA support: {}",
        swift_help.stdout
    );

    let macho_classdump_help: Run = run_disrobe(&["macho", "classdump", "--help"]);
    assert_eq!(
        macho_classdump_help.code, 0,
        "stderr: {}",
        macho_classdump_help.stderr
    );
    assert!(
        !macho_classdump_help.stdout.contains(".ipa"),
        "macho classdump help must not advertise IPA support: {}",
        macho_classdump_help.stdout
    );

    let macho_dump_help: Run = run_disrobe(&["macho", "dump", "--help"]);
    assert_eq!(
        macho_dump_help.code, 0,
        "stderr: {}",
        macho_dump_help.stderr
    );
    assert!(
        macho_dump_help.stdout.contains(".ipa"),
        "macho dump help must retain IPA support: {}",
        macho_dump_help.stdout
    );

    let shield_help: Run = run_disrobe(&["swift", "shield-undo", "--help"]);
    assert_eq!(shield_help.code, 0, "stderr: {}", shield_help.stderr);
    assert!(shield_help.stdout.contains("parse a SwiftShield"));
    assert!(shield_help.stdout.contains("rename mapping"));
    assert!(
        !shield_help.stdout.contains("reverse a SwiftShield"),
        "shield-undo help must describe parsing rather than automatic undo: {}",
        shield_help.stdout
    );
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-missing", "bin");
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-plain-py", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-plain-py-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-dry", "py");
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dry");
    let out_dir: PathBuf = out_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("status-empty");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("status-empty-json");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("init-default");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("init-claude");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("init-already");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("init-force");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("man-out");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("bug-report");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("comp-install");
    let work: PathBuf = work_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-pyinstaller", "exe");
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
    let (_missing_scratch, missing): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("missing-pi", "exe");
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
    let (_blob_scratch, blob): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-pyfreeze", "bin");
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
    let (_blob_scratch, blob): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("plain-pe", "exe");
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
    let (_blob_scratch, blob): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-onefile", "bin");
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
    let (_blob_scratch, blob): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-pyc", "pyc");
    write_bytes(&blob, b"not a pyc file");
    let r: Run = run_disrobe(&["py", "disasm", blob.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("DR-CLI-0051") || r.stderr.contains("pyc"));
}

#[test]
fn py_deob_passes_through_clean_source() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("clean-py", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py-deob-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("cleanup-py", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py-deob-cleanup-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_blob_scratch, blob): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-pye", "pye");
    write_bytes(&blob, b"this is not a sourcedefender envelope");
    let r: Run = run_disrobe(&["py", "sourcedefender", blob.to_str().unwrap()]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("DR-") || r.stderr.to_lowercase().contains("sourcedefender"));
}

#[test]
fn js_deob_handles_minimal_string_array_obfuscator_pattern() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("js-strarr", "js");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-deob-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("js-pipeline", "js");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-pipeline-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
fn js_deob_full_routes_jsconfuser_to_dedicated_pipeline() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jsconfuser-full", "js");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("jsconfuser-full-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
    let out_path: PathBuf = out_dir.join("jsconfuser-full.deobfuscated.js");
    write_bytes(
        &src,
        br#"var P={_compress:function(){},_decompress:function(){},decompressFromBase64:function(v){return v;}};
var msg = P.decompressFromBase64("BYUwNmD2Q===");
console.log(msg);
"#,
    );
    let r: Run = run_disrobe(&[
        "js",
        "deob",
        src.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--full",
    ]);
    assert_eq!(r.code, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);
    assert!(r.stdout.contains("family:                    JsConfuser"));
    assert!(r.stdout.contains("string compression blocks: 1"));
    let recovered: String = std::fs::read_to_string(&out_path).expect("read recovered");
    assert!(recovered.contains("var msg = \"hello\";"));
    let pipeline: String =
        std::fs::read_to_string(out_path.with_extension("pipeline.json")).expect("read pipeline");
    assert!(pipeline.contains("\"string_compression_blocks_reversed\": 1"));
}

#[test]
fn auto_native_deobf_json_surfaces_copyprop_and_mba_on_unpacked_image() {
    let packed: PathBuf = corpus_path("native/packers/aspack/Clockres.packed.aspack.exe");
    assert!(
        packed.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        packed.display()
    );
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("native-deobf-surface");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
    let r: Run = run_disrobe(&[
        "auto",
        packed.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}\nstdout: {}", r.stderr, r.stdout);

    let deobf_json: PathBuf = out_dir.join("extracted").join("deobf.json");
    assert!(
        deobf_json.exists(),
        "the aspack-unpacked image must yield a deobf.json child:\n{}",
        r.stdout
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&deobf_json).expect("read deobf.json"))
            .expect("deobf.json must be valid JSON");

    let copyprop: &Vec<serde_json::Value> = parsed
        .get("copyprop_report")
        .and_then(serde_json::Value::as_array)
        .expect("copyprop_report field must be present");
    assert!(
        copyprop.iter().any(|b: &serde_json::Value| {
            b.get("report")
                .and_then(|r: &serde_json::Value| r.get("changed"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }),
        "copyprop_report must carry at least one block with a real reduction: {copyprop:?}"
    );

    let mba: &Vec<serde_json::Value> = parsed
        .get("mba_simplifications")
        .and_then(serde_json::Value::as_array)
        .expect("mba_simplifications field must be present");
    assert!(
        mba.iter().any(|m: &serde_json::Value| {
            m.get("simplification")
                .and_then(|s: &serde_json::Value| s.get("proven"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        }),
        "mba_simplifications must carry a proven opaque-predicate reduction: {mba:?}"
    );

    assert!(
        parsed.get("pathsense_report").is_some(),
        "pathsense_report field must serialize (null or populated) so the capability is reachable"
    );

    let listing: &str = parsed
        .get("cleaned_listing")
        .and_then(serde_json::Value::as_str)
        .expect("cleaned_listing must be present");
    assert!(
        listing.contains("copy-propagation") && listing.contains("MBA-simplified"),
        "the cleaned listing must annotate the newly-wired defeats"
    );
}

#[test]
fn js_deob_rejects_non_utf8_input() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("js-non-utf8", "js");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-non-utf8-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-empty", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-decompile-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-bad-magic", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-bad-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("not-pyarmor", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("pyarmor-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_missing_scratch, missing): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("missing-pyarmor", "py");
    let _ = std::fs::remove_file(&missing);
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("pyarmor-missing-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    assert!(
        r.stdout.contains("PyOxidizer (experimental, unvalidated)"),
        "PyOxidizer must be qualified in pyfreeze help:\n{}",
        r.stdout
    );
}

#[test]
fn pyfreeze_extract_qualifies_pyoxidizer_success_output() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("pyoxidizer-output-label", "exe");
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("pyoxidizer-output-label-out");
    let out_dir: PathBuf = out_scratch.path().to_path_buf();
    let mut container: Vec<u8> = b"MZ\0PyOxidizer\0python312.dll\0pyembed\x03".to_vec();
    container.push(0);
    container.extend_from_slice(&1u32.to_le_bytes());
    container.extend_from_slice(&0u32.to_le_bytes());
    container.extend_from_slice(&1u32.to_le_bytes());
    container.push(0);
    container.push(0);
    write_bytes(&input, &container);

    let r: Run = run_disrobe(&[
        "pyfreeze",
        "extract",
        input.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout
            .contains("kind:            PyOxidizer (experimental, unvalidated)"),
        "PyOxidizer must be qualified in successful extraction output:\n{}",
        r.stdout
    );
    let manifest_bytes: Vec<u8> =
        std::fs::read(out_dir.join("manifest.json")).expect("read pyfreeze manifest");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse pyfreeze manifest");
    assert_eq!(
        manifest.get("kind").and_then(serde_json::Value::as_str),
        Some("py-oxidizer")
    );
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
fn pyarmor_help_describes_bcc_as_in_tree_static_analysis() {
    let r: Run = run_disrobe(&["pyarmor", "unpack", "--help"]);
    assert_eq!(r.code, 0);
    let bcc_help: String = r
        .stdout
        .lines()
        .skip_while(|line: &&str| line.trim() != "--allow-bcc")
        .skip(1)
        .take_while(|line: &&str| !line.starts_with("      --mode"))
        .map(str::trim)
        .collect::<Vec<&str>>()
        .join(" ");
    assert!(bcc_help.contains("in-tree static analysis"));
    assert!(bcc_help.contains("does not execute the sample"));
    assert!(
        bcc_help.contains("does not execute the sample or invoke external tools"),
        "BCC option description: {bcc_help}"
    );
    assert!(!bcc_help.to_ascii_lowercase().contains("ghidra"));
    assert!(!bcc_help.contains("subprocess"));
}

#[test]
fn pyarmor_help_describes_reconstructed_pyc() {
    let r: Run = run_disrobe(&["pyarmor", "unpack", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("reconstructed .pyc"));
    assert!(!r.stdout.contains("original .pyc"));
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
fn wasm_cli_copy_distinguishes_transform_and_classify_only_families() {
    let deob_help: Run = run_disrobe(&["wasm", "deob", "--help"]);
    assert_eq!(deob_help.code, 0, "stderr: {}", deob_help.stderr);
    assert!(
        deob_help.stdout.contains("transforms 3 families")
            && deob_help
                .stdout
                .contains("Tigress -> Emscripten classify-only")
            && deob_help
                .stdout
                .contains("wasm-name-obfuscator classify-only"),
        "wasm deob help must distinguish transformed and classify-only families:\n{}",
        deob_help.stdout
    );

    let passes: Run = run_disrobe(&["passes"]);
    assert_eq!(passes.code, 0, "stderr: {}", passes.stderr);
    assert!(
        passes.stdout.contains("3 transform families")
            && passes.stdout.contains("Tigress classify-only")
            && passes.stdout.contains("wasm-name-obfuscator classify-only"),
        "passes output must distinguish transformed and classify-only families:\n{}",
        passes.stdout
    );
}

#[test]
fn native_identify_qualifies_pyoxidizer_output_without_changing_json_name() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("native-identify-pyoxidizer", "exe");
    let (_report_scratch, report_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("native-identify-pyoxidizer-report", "json");
    write_bytes(&input, b"MZ\0pyoxidizer\0embedded-python-runtime");

    let r: Run = run_disrobe(&[
        "native",
        "identify",
        input.to_str().unwrap(),
        "--out",
        report_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("PyOxidizer (experimental, unvalidated)"),
        "PyOxidizer must be qualified in native identify output:\n{}",
        r.stdout
    );

    let report_bytes: Vec<u8> = std::fs::read(&report_path).expect("read identity report");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse identity report");
    let hits: &[serde_json::Value] = report
        .get("hits")
        .and_then(serde_json::Value::as_array)
        .expect("identity report hits");
    let pyoxidizer: &serde_json::Value = hits
        .iter()
        .find(|hit: &&serde_json::Value| {
            hit.get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name: &str| name.contains("PyOxidizer"))
        })
        .expect("PyOxidizer identity hit");
    assert_eq!(
        pyoxidizer.get("name").and_then(serde_json::Value::as_str),
        Some("PyOxidizer")
    );
}

#[test]
fn wasm_decompile_target_rust_emits_rs_file() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-lift-rust", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-lift-rust-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-lift-ts", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-lift-ts-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-lift-wat", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-lift-wat-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-emit", "wasm");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("wasm-emit-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("verify-bogus", "dr");
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("chain-py", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("chain-py-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("chain-bad", "py");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("chain-bad-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("native-decomp", "bin");
    write_bytes(
        &bogus,
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
    );
    let r: Run = run_disrobe(&["native", "decompile", bogus.to_str().unwrap()]);
    if r.code == 0 {
        return;
    }
    assert!(
        r.stderr.contains("DR-NATIVE-0147")
            || r.stderr.contains("DR-NATIVE-0001")
            || r.stderr.contains("ghidra"),
        "expected a clear native-decompile diagnostic, got: {}",
        r.stderr
    );
}

#[test]
fn native_symbols_on_minimal_elf_emits_json() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("native-syms", "bin");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("native-syms-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("py-decomp-bad", "pyc");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py-decomp-bad-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("py-extract-bad", "bin");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py-extract-bad-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    let (_bogus_scratch, bogus): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("py-disasm-emit-bad", "pyc");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py-disasm-emit-out");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
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
    assert_ne!(
        r.code, 0,
        "a closed stdin gives the LSP daemon no initialize request, so it must fail; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stderr.contains("DR-CLI-0201"),
        "the failure must name its DR code so a caller can look it up; stderr={}",
        r.stderr
    );
    assert!(
        r.stdout.is_empty(),
        "stdout is the LSP JSON-RPC channel and must carry no diagnostics; stdout={}",
        r.stdout
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

const TAINTED_WASM_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (result i32)
    (call $system (call $recv))))
"#;

const SEVERED_WASM_WAT: &str = r#"
(module
  (import "env" "recv" (func $recv (result i32)))
  (import "env" "system" (func $system (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handle") (param i32) (result i32)
    (if (result i32) (local.get 0)
      (then (drop (call $recv)) (i32.const 0))
      (else (call $system (i32.const 7))))))
"#;

fn write_wasm(stem: &str, wat: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat fixture");
    let (scratch, path): (disrobe_core::scratch::ScratchDir, PathBuf) = temp_path(stem, "wasm");
    write_bytes(&path, &bytes);
    (scratch, path)
}

fn corpus_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

const GC_STRUCT_WAT: &str = r#"
    (module
      (rec
        (type $shape (sub (struct (field $kind i32))))
        (type $circle (sub $shape (struct (field $kind i32) (field $r (mut i32))))))
      (type $row (array (mut i32)))
      (func (export "make_circle") (result (ref $circle))
        i32.const 0 i32.const 7 struct.new $circle)
      (func (export "make_row") (result (ref $row))
        i32.const 3 i32.const 1 array.new $row))
"#;

const APK_V2V3_SIGNER_SHA256: &str =
    "f8b7664fada9b0f39d7a972abb28c137095c6532091e98df4f113b31bf23d49c";

#[test]
fn mobile_recon_surfaces_the_signer_cert_fingerprint_on_a_signed_apk() {
    let apk: PathBuf = corpus_path("apk/fixture-v2v3-signed.apk");
    assert!(
        apk.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        apk.display()
    );
    let r: Run = run_disrobe(&["mobile", "recon", apk.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains(APK_V2V3_SIGNER_SHA256),
        "mobile recon must print the APK Signing Block signer cert SHA-256 matching the keytool oracle:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("block present"),
        "recon must report the signing block as present:\n{}",
        r.stdout
    );
}

#[test]
fn mobile_recon_json_carries_the_signer_fingerprint_machine_clean() {
    let apk: PathBuf = corpus_path("apk/fixture-v2v3-signed.apk");
    assert!(
        apk.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        apk.display()
    );
    let r: Run = run_disrobe(&["mobile", "recon", apk.to_str().unwrap(), "--json"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("mobile recon --json emits valid json");
    assert_eq!(
        parsed["signing"]["signing_block_present"], true,
        "stdout: {}",
        r.stdout
    );
    let fp: &str =
        parsed["signing"]["schemes"][0]["signers"][0]["certificates"][0]["sha256_fingerprint"]
            .as_str()
            .expect("fingerprint string present");
    assert_eq!(fp, APK_V2V3_SIGNER_SHA256, "stdout: {}", r.stdout);
}

#[test]
fn jvm_retrace_maps_an_inlined_obfuscated_frame_to_the_original() {
    let mapping: PathBuf = corpus_path("jvm/proguard/mapping.txt");
    assert!(
        mapping.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        mapping.display()
    );
    let r: Run = run_disrobe(&[
        "jvm",
        "retrace",
        "--mapping",
        mapping.to_str().unwrap(),
        "--class",
        "Hello",
        "--method",
        "main",
        "--line",
        "1012",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("Hello.bumpCounter:12"),
        "the obfuscated frame Hello.main:1012 must retrace through the inline to Hello.bumpCounter:12:\n{}",
        r.stdout
    );
}

#[test]
fn jvm_retrace_json_carries_the_retraced_frames() {
    let mapping: PathBuf = corpus_path("jvm/proguard/mapping.txt");
    assert!(
        mapping.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        mapping.display()
    );
    let r: Run = run_disrobe(&[
        "jvm",
        "retrace",
        "--mapping",
        mapping.to_str().unwrap(),
        "--class",
        "Hello",
        "--method",
        "main",
        "--line",
        "1012",
        "--json",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("jvm retrace --json emits valid json");
    let frames: &Vec<serde_json::Value> =
        parsed["frames"].as_array().expect("frames array present");
    assert!(
        frames
            .iter()
            .any(|f: &serde_json::Value| f["method_name"] == "bumpCounter"
                && f["original_line"] == 12),
        "retraced frames must include bumpCounter:12:\n{}",
        r.stdout
    );
}

#[test]
fn wasm_lift_gc_emits_reconstructed_gc_struct_and_array_types() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        write_wasm("wasm-lift-gc", GC_STRUCT_WAT);
    let r: Run = run_disrobe(&["wasm", "lift-gc", src.to_str().unwrap(), "--json"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("wasm lift-gc --json emits valid json");
    let struct_count: usize = parsed["structs"]
        .as_object()
        .map_or(0, serde_json::Map::len);
    let array_count: usize = parsed["arrays"].as_object().map_or(0, serde_json::Map::len);
    assert!(
        struct_count >= 2,
        "lift-gc must reconstruct the two GC struct types:\n{}",
        r.stdout
    );
    assert!(
        array_count >= 1,
        "lift-gc must reconstruct the GC array type:\n{}",
        r.stdout
    );
    let rust: &str = parsed["rust_source"].as_str().expect("rust_source present");
    assert!(
        rust.contains("pub struct Struct"),
        "lift-gc must emit typed Rust struct source:\n{rust}"
    );
}

#[test]
#[cfg(feature = "dotnet")]
fn dotnet_recover_iterators_surfaces_the_move_next_bodies() {
    let dll: PathBuf = corpus_path("dotnet/constructs/Constructs.dll");
    assert!(
        dll.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dll.display()
    );
    let r: Run = run_disrobe(&[
        "dotnet",
        "decompile",
        dll.to_str().unwrap(),
        "--recover-iterators",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("MoveNext"),
        "recover-iterators must surface the MoveNext state-machine body:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("yield return"),
        "the recovered iterator MoveNext must carry the reconstructed `yield return`:\n{}",
        r.stdout
    );
}

#[test]
#[cfg(feature = "dotnet")]
fn dotnet_recover_iterators_json_carries_yield_and_await_bodies() {
    let dll: PathBuf = corpus_path("dotnet/constructs/Constructs.dll");
    assert!(
        dll.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dll.display()
    );
    let r: Run = run_disrobe(&[
        "dotnet",
        "decompile",
        dll.to_str().unwrap(),
        "--recover-iterators",
        "--json",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("dotnet recover-iterators --json emits valid json");
    let bodies: &Vec<serde_json::Value> = parsed["move_next_bodies"]
        .as_array()
        .expect("move_next_bodies array present");
    assert!(
        bodies.iter().any(|m: &serde_json::Value| m["body"]
            .as_str()
            .is_some_and(|b| b.contains("yield return"))),
        "a recovered MoveNext body must carry yield return:\n{}",
        r.stdout
    );
    assert!(
        bodies
            .iter()
            .any(|m: &serde_json::Value| m["body"].as_str().is_some_and(|b| b.contains("await"))),
        "a recovered MoveNext body must carry await (async state machine):\n{}",
        r.stdout
    );
}

#[test]
#[cfg(feature = "dotnet")]
fn sentinel_plus_return_is_not_an_unlowered_compiler_construct_refusal() {
    let body: &str = concat!(
        "private void MoveNext()\n",
        "{\n",
        "    throw new System.NotSupportedException(\"disrobe: compiler-generated construct not lowered\");\n",
        "    return;\n",
        "}\n"
    );
    assert!(!is_unlowered_compiler_construct_refusal(body));
}

#[test]
#[cfg(feature = "dotnet")]
fn dotnet_recover_iterators_json_refuses_count_with_async_cached_lambda_field() {
    let dll: PathBuf = corpus_path("dotnet/megafile/EdgeCases.baseline.dll");
    assert!(
        dll.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        dll.display()
    );
    let r: Run = run_disrobe(&[
        "dotnet",
        "decompile",
        dll.to_str().unwrap(),
        "--recover-iterators",
        "--json",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("dotnet recover-iterators --json emits valid json");
    let bodies: &Vec<serde_json::Value> = parsed["move_next_bodies"]
        .as_array()
        .expect("move_next_bodies array present");
    let count_with_async: &serde_json::Value = bodies
        .iter()
        .find(|body: &&serde_json::Value| {
            body["signature"].as_str().is_some_and(|signature: &str| {
                signature.contains("<CountWithAsync>d__1") && signature.contains("MoveNext(")
            })
        })
        .expect("CountWithAsync MoveNext state-machine body present in iterator JSON");
    let body: &str = count_with_async["body"]
        .as_str()
        .expect("CountWithAsync MoveNext body present in iterator JSON");
    assert!(
        is_unlowered_compiler_construct_refusal(body),
        "CountWithAsync MoveNext must state the live unlowered compiler-construct refusal instead of emitting compiler-generated plumbing:\n{body}"
    );
    assert!(
        !body
            .lines()
            .filter(|line: &&str| !line.trim_start().starts_with("//"))
            .any(|line: &str| line.contains("__9__1_0")),
        "CountWithAsync MoveNext must not emit the stripped cached-lambda field as live code:\n{body}"
    );
}

#[test]
fn taint_reports_recv_feeding_system_in_a_lifted_wasm_module() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        write_wasm("taint-tainted", TAINTED_WASM_WAT);
    let r: Run = run_disrobe(&["taint", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("wasm"),
        "expected the lifted source language in output:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("recv -> system"),
        "the recv result is the direct argument to system, so the flow must surface:\n{}",
        r.stdout
    );
}

#[test]
fn taint_finds_no_flow_when_source_and_sink_sit_on_opposite_branches() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        write_wasm("taint-severed", SEVERED_WASM_WAT);
    let r: Run = run_disrobe(&["taint", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("flows: 0"),
        "recv and system are on mutually exclusive arms, so no real flow exists:\n{}",
        r.stdout
    );
}

#[test]
fn taint_json_carries_the_source_to_sink_finding() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        write_wasm("taint-json", TAINTED_WASM_WAT);
    let r: Run = run_disrobe(&[
        "taint",
        src.to_str().unwrap(),
        "--source",
        "recv",
        "--sink",
        "system",
        "--json",
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("taint --json emits valid json");
    assert_eq!(parsed["finding_count"], 1, "stdout: {}", r.stdout);
    assert_eq!(parsed["findings"][0]["source_symbol"], "recv");
    assert_eq!(parsed["findings"][0]["sink_symbol"], "system");
    assert_eq!(
        parsed["findings"][0]["path"]
            .as_array()
            .expect("finding path is an array")
            .iter()
            .filter(|step: &&serde_json::Value| step["kind"] == "call-definite")
            .count(),
        2,
        "the external source and sink each retain their normalized call label"
    );
    assert_eq!(
        parsed["call_edges"]
            .as_array()
            .expect("call edges are an array")
            .iter()
            .filter(|edge: &&serde_json::Value| edge["label"]["kind"] == "definite")
            .count(),
        2
    );
}

#[test]
fn taint_json_labels_the_stripped_native_twins_exact_direct_edges() {
    let stripped: PathBuf = corpus_path("native/discovery/disc.stripped.elf");
    let unstripped: PathBuf = corpus_path("native/discovery/disc.unstripped.elf");
    assert!(stripped.exists(), "{} must be tracked", stripped.display());
    assert!(
        unstripped.exists(),
        "{} must be tracked",
        unstripped.display()
    );

    let r: Run = run_disrobe(&["taint", stripped.to_str().unwrap(), "--json"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("native taint --json emits valid json");
    let edges: &[serde_json::Value] = parsed["call_edges"]
        .as_array()
        .expect("native taint JSON carries call edges");

    let twin_bytes: Vec<u8> = std::fs::read(&unstripped).expect("read unstripped twin");
    let twin = disrobe_pass_native::build_disasm_payload(&twin_bytes)
        .expect("unstripped twin disassembles");
    let mut names_by_address: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for symbol in &twin.symbol_table {
        names_by_address
            .entry(symbol.address)
            .or_default()
            .insert(symbol.name.as_str());
    }
    let recovered: BTreeSet<(u64, u64)> = edges
        .iter()
        .filter(|edge: &&serde_json::Value| edge["label"]["kind"] == "definite")
        .filter_map(|edge: &serde_json::Value| {
            Some((edge["site"].as_u64()?, edge["label"]["target"].as_u64()?))
        })
        .collect();
    let truth_names: BTreeSet<&str> =
        BTreeSet::from(["add", "compute", "dispatch", "mul", "sum_to"]);
    let truth_targets: BTreeSet<u64> = names_by_address
        .iter()
        .filter(|(_address, names): &(&u64, &BTreeSet<&str>)| !names.is_disjoint(&truth_names))
        .map(|(address, _names): (&u64, &BTreeSet<&str>)| *address)
        .collect();
    assert_eq!(truth_targets.len(), 5);
    let truth: BTreeSet<(u64, u64)> = twin
        .instructions
        .iter()
        .filter(|instruction| instruction.flow == disrobe_ir::payload::InsnFlow::Call)
        .filter_map(|instruction| {
            let target: u64 = instruction.branch_target?;
            truth_targets
                .contains(&target)
                .then_some((instruction.offset, target))
        })
        .collect();
    let true_positive_count: usize = recovered.intersection(&truth).count();

    assert_eq!(recovered, truth, "call-site and target pairs must agree");
    assert_eq!(
        (true_positive_count, recovered.len(), truth.len()),
        (truth.len(), truth.len(), truth.len()),
        "precision {}/{} and recall {}/{}",
        true_positive_count,
        recovered.len(),
        true_positive_count,
        truth.len()
    );
}

fn go_fixture(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("disrobe-pass-go");
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

#[test]
fn js_recover_sources_reconstructs_the_deployed_tree_byte_identical() {
    let bundle: PathBuf = corpus_path("js/esbuild/bundle.js");
    assert!(
        bundle.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        bundle.display()
    );
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-recover-sources");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
    let r: Run = run_disrobe(&[
        "js",
        "deob",
        bundle.to_str().unwrap(),
        "--recover-sources",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("js recover-sources: OK"),
        "stdout: {}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("byte-identical (sourcesContent present): 4"),
        "the esbuild bundle map carries sourcesContent for all 4 originals:\n{}",
        r.stdout
    );

    for basename in ["index.js", "math.js", "util.js", "lazy.js"] {
        let recovered: PathBuf = out_dir.join("src").join(basename);
        assert!(
            recovered.is_file(),
            "recovered tree must contain src/{basename}:\n{}",
            r.stdout
        );
        let got: Vec<u8> = std::fs::read(&recovered).expect("read recovered");
        let want: Vec<u8> = std::fs::read(corpus_path(&format!("js/esbuild/src/{basename}")))
            .expect("read original");
        assert_eq!(
            got, want,
            "src/{basename} must reconstruct byte-for-byte from the committed pre-bundle original"
        );
    }
}

#[test]
fn sourcedefender_modern_body_decrypts_with_a_supplied_known_key() {
    let pye: PathBuf = corpus_path("python/sourcedefender/crafted_modern_aesgcm_known_key.pye");
    assert!(
        pye.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        pye.display()
    );
    let (_out_py_scratch, out_py): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("sdef-modern", "py");
    let key_hex: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let r: Run = run_disrobe(&[
        "py",
        "sourcedefender",
        pye.to_str().unwrap(),
        "--key",
        key_hex,
        "--out",
        out_py.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("variant:      modern-hex"),
        "modern body must classify as modern-hex:\n{}",
        r.stdout
    );
    let recovered: String = std::fs::read_to_string(&out_py).expect("read recovered source");
    let original: String = std::fs::read_to_string(corpus_path(
        "python/sourcedefender/crafted_modern_aesgcm_known_key.py",
    ))
    .expect("read original source");
    assert_eq!(
        recovered.trim_end(),
        original.trim_end(),
        "the supplied known key must recover the original source byte-for-byte"
    );
}

#[test]
fn sourcedefender_modern_body_without_key_walls_honestly() {
    let pye: PathBuf = corpus_path("python/sourcedefender/known_v16_trial.pye");
    assert!(
        pye.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        pye.display()
    );
    let r: Run = run_disrobe(&["py", "sourcedefender", pye.to_str().unwrap()]);
    assert_ne!(
        r.code, 0,
        "a runtime-key modern body must not claim recovery"
    );
    assert!(
        r.stdout.contains("runtime-license-key") || r.stderr.contains("runtime-license-key"),
        "the default modern wall must name the runtime-license-key reason:\nout:{}\nerr:{}",
        r.stdout,
        r.stderr
    );
}

#[test]
fn go_recover_renders_build_info_matching_the_embedded_blob() {
    let exe: PathBuf = go_fixture("hello_deps.exe");
    if !exe.is_file() {
        return;
    }
    let (_out_json_scratch, out_json): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("go-deps", "json");
    let r: Run = run_disrobe(&[
        "go",
        "recover",
        exe.to_str().unwrap(),
        "--out",
        out_json.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("build info (runtime/debug.BuildInfo):"),
        "go recover must render the build_info block:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("example.com/depmod"),
        "build_info deps must surface the declared dependency:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("=>"),
        "the local replace directive must render with a `=>` arrow:\n{}",
        r.stdout
    );
    let analysis: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_json).expect("read analysis json"))
            .expect("analysis json parses");
    let deps: &serde_json::Value = &analysis["moduledata"]["build_info"]["deps"];
    assert_eq!(
        deps[0]["path"], "example.com/depmod",
        "the analysis JSON must carry the recovered build_info deps:\n{deps}"
    );
    assert!(
        analysis["moduledata"]["build_info"]["deps"][0]["replace"].is_object(),
        "the JSON dep must carry the replace directive object"
    );
}

#[test]
fn go_info_renders_build_info_settings() {
    let exe: PathBuf = go_fixture("hello_normal.exe");
    assert!(
        exe.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        exe.display()
    );
    let r: Run = run_disrobe(&["go", "info", exe.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("build info (runtime/debug.BuildInfo):"),
        "go info must render the build_info block:\n{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("GOOS=") && r.stdout.contains("GOARCH="),
        "build settings GOOS/GOARCH must render:\n{}",
        r.stdout
    );
}
