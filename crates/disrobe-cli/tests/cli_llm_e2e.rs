#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::same_item_push
)]

use std::path::PathBuf;
use std::process::Command;

use jsonschema::Validator;
use serde_json::Value as Json;

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
    let purpose: String = format!("disrobe-llm-e2e-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let path: PathBuf = scratch.path().join(format!("payload.{ext}"));
    (scratch, path)
}

const REAL_PYC: &str =
    "corpus/python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc";

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn write_decodable_pyc(path: &PathBuf) {
    let source: PathBuf = workspace_root().join(REAL_PYC);
    assert!(
        source.is_file(),
        "{REAL_PYC} is tracked in git and every case here decompiles it, so its absence is a \
         damaged checkout rather than an optional dependency: {}",
        source.display()
    );
    std::fs::copy(&source, path).expect("stage the committed pyc");
}

fn run_disrobe(args: &[&str]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli`",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn schema_root() -> Json {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("schemas");
    p.push("disrobe-metadata-llm-v1.json");
    let bytes: Vec<u8> =
        std::fs::read(&p).unwrap_or_else(|e| panic!("read schema {}: {e}", p.display()));
    serde_json::from_slice(&bytes).expect("schema parse")
}

#[test]
fn llm_flag_help_lists_metadata_options() {
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&["--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("--llm"), "help missing --llm:\n{stdout}");
    assert!(stdout.contains("--metadata-pack-1"));
    assert!(stdout.contains("--metadata-format"));
}

#[test]
fn unknown_metadata_format_errors_with_dr_cli_0440() {
    let (code, _stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--metadata-format",
        "xml",
        "py",
        "decompile",
        "/nonexistent",
    ]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0440") || stderr.contains("--metadata-format"),
        "expected DR-CLI-0440, stderr={stderr}"
    );
}

#[test]
fn decryption_keys_without_auth_errors_with_dr_cli_0420() {
    let (code, _stdout, stderr): (i32, String, String) =
        run_disrobe(&["--decryption-keys", "py", "decompile", "/nonexistent"]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0420") || stderr.contains("decryption-keys"),
        "expected DR-CLI-0420, stderr={stderr}"
    );
}

#[test]
fn no_llm_flags_writes_no_bundle() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("noflag", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("noflag-out", "dir");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let (code, stdout, stderr): (i32, String, String) =
        run_disrobe(&["py", "decompile", &pyc_str, "--out", &out_str]);
    assert_eq!(
        code, 0,
        "the run must succeed, or this case proves nothing about what a successful run writes \
         without the flags:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let bundle_path: PathBuf = out_dir.join("py-decompile.disrobe.llm.json");
    assert!(
        !bundle_path.exists(),
        "must not write a bundle without --llm"
    );
}

#[test]
fn llm_briefs_writes_agents_and_skill_markdown() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs-out", "dir");
    let (_bundle_out_scratch, bundle_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("briefs-bundle", "json");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();

    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm-briefs",
        "--metadata-out",
        &bundle_str,
        "--force",
        "py",
        "decompile",
        &pyc_str,
        "--out",
        &out_str,
    ]);
    assert_eq!(
        code, 0,
        "the run this case grades must succeed, or the bundle it inspects never exists and the \
         case reports success while checking nothing:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        bundle_out.exists(),
        "the run was asked to write {} and this case reads it, so a missing bundle is the defect \
         this case exists to catch:\nstdout=\n{stdout}\nstderr=\n{stderr}",
        bundle_out.display()
    );

    let bundle_dir: &std::path::Path = bundle_out.parent().expect("bundle parent");
    let agents_path: PathBuf = bundle_dir.join("AGENTS.md");
    let skill_path: PathBuf = bundle_dir.join("SKILL.md");

    assert!(agents_path.exists(), "AGENTS.md not written");
    assert!(skill_path.exists(), "SKILL.md not written");

    let agents: String = std::fs::read_to_string(&agents_path).expect("read AGENTS.md");
    let skill: String = std::fs::read_to_string(&skill_path).expect("read SKILL.md");

    assert!(!agents.trim().is_empty(), "AGENTS.md is empty");
    assert!(!skill.trim().is_empty(), "SKILL.md is empty");

    assert!(
        agents.starts_with("# AGENTS.md"),
        "AGENTS.md missing header"
    );
    assert!(
        agents.contains("## Artifact"),
        "AGENTS.md missing artifact section"
    );
    assert!(
        agents.contains("disrobe.metadata.llm.v1"),
        "AGENTS.md missing schema reference"
    );

    assert!(skill.starts_with("---\n"), "SKILL.md missing frontmatter");
    assert!(
        skill.contains("name: reconstruct-"),
        "SKILL.md missing skill name"
    );
    assert!(
        skill.contains("## Reconstruction procedure"),
        "SKILL.md missing procedure"
    );

    let rerun: String = std::fs::read_to_string(&agents_path).expect("reread AGENTS.md");
    assert_eq!(agents, rerun, "AGENTS.md must be stable");
}

#[test]
fn llm_flag_writes_schema_conforming_bundle() {
    let (_pyc_scratch, pyc): (disrobe_core::scratch::ScratchDir, PathBuf) = temp_path("llm", "pyc");
    write_decodable_pyc(&pyc);
    let (_out_dir_scratch, out_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("llm-out", "dir");
    let (_bundle_out_scratch, bundle_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("llm-bundle", "json");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();

    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--i-have-authorization",
        "--metadata-out",
        &bundle_str,
        "--force",
        "py",
        "decompile",
        &pyc_str,
        "--out",
        &out_str,
    ]);
    assert_eq!(
        code, 0,
        "the run this case grades must succeed, or the bundle it inspects never exists and the \
         case reports success while checking nothing:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        bundle_out.exists(),
        "the run was asked to write {} and this case reads it, so a missing bundle is the defect \
         this case exists to catch:\nstdout=\n{stdout}\nstderr=\n{stderr}",
        bundle_out.display()
    );
    let bytes: Vec<u8> = std::fs::read(&bundle_out).expect("read bundle");
    let bundle: Json = serde_json::from_slice(&bytes).expect("parse bundle");
    assert_eq!(
        bundle.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
    let schema: Json = schema_root();
    let validator: Validator = jsonschema::validator_for(&schema).expect("compile");
    let errors: Vec<String> = validator
        .iter_errors(&bundle)
        .map(|e: jsonschema::ValidationError<'_>| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "bundle failed schema:\n{}\nbundle={}",
        errors.join("\n"),
        serde_json::to_string_pretty(&bundle).unwrap()
    );
}
