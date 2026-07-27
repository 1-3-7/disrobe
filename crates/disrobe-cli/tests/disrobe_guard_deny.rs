#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_root(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-guard-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn guard_check(path: &Path, extra: &[&str]) -> Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    let mut cmd: Command = Command::new(&bin);
    cmd.arg("guard").arg("check").arg(path);
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

#[test]
fn guard_denies_stage_output_and_allows_src() {
    let root_scratch: disrobe_core::scratch::ScratchDir = tmp_root("denyallow");
    let root: PathBuf = root_scratch.path().to_path_buf();
    let stage_dir: PathBuf = root
        .join("out")
        .join("demo-chain")
        .join("stages")
        .join("00-input");
    std::fs::create_dir_all(&stage_dir).expect("mk stage dir");
    let stage_output: PathBuf = stage_dir.join("output.bin");
    std::fs::write(&stage_output, b"stage-bytes").expect("write stage output");

    let src_dir: PathBuf = root.join("src");
    std::fs::create_dir_all(&src_dir).expect("mk src dir");
    let src_file: PathBuf = src_dir.join("foo.rs");
    std::fs::write(&src_file, b"fn main() {}").expect("write src");

    let deny: Output = guard_check(&stage_output, &[]);
    let deny_out: String = String::from_utf8_lossy(&deny.stdout).into_owned();
    let deny_err: String = String::from_utf8_lossy(&deny.stderr).into_owned();
    assert!(
        !deny.status.success(),
        "guard must DENY a stage output (non-zero exit); stdout={deny_out} stderr={deny_err}"
    );
    assert!(
        deny_out.contains("DR-CLI-0320") || deny_err.contains("DR-CLI-0320"),
        "deny must surface DR-CLI-0320; stdout={deny_out} stderr={deny_err}"
    );

    let allow: Output = guard_check(&src_file, &[]);
    let allow_out: String = String::from_utf8_lossy(&allow.stdout).into_owned();
    let allow_err: String = String::from_utf8_lossy(&allow.stderr).into_owned();
    assert!(
        allow.status.success(),
        "guard must ALLOW an unrelated src file; stdout={allow_out} stderr={allow_err}"
    );
    assert!(
        allow_out.contains("guard allow"),
        "allow must print `guard allow`; stdout={allow_out}"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn guard_json_reports_machine_decision() {
    let root_scratch: disrobe_core::scratch::ScratchDir = tmp_root("json");
    let root: PathBuf = root_scratch.path().to_path_buf();
    let stage_dir: PathBuf = root.join("out").join("x").join("final");
    std::fs::create_dir_all(&stage_dir).expect("mk final dir");
    let stage_output: PathBuf = stage_dir.join("01-pyarmor-unpack");
    std::fs::write(&stage_output, b"final-bytes").expect("write final");

    let src_dir: PathBuf = root.join("workspace");
    std::fs::create_dir_all(&src_dir).expect("mk workspace");
    let src_file: PathBuf = src_dir.join("notes.txt");
    std::fs::write(&src_file, b"notes").expect("write notes");

    let deny: Output = guard_check(&stage_output, &["--json"]);
    let deny_out: String = String::from_utf8_lossy(&deny.stdout).into_owned();
    assert!(
        !deny.status.success(),
        "json deny must still fail; stdout={deny_out}"
    );
    assert!(
        deny_out.contains("\"decision\": \"deny\"") || deny_out.contains("\"decision\":\"deny\""),
        "json deny must contain decision=deny; stdout={deny_out}"
    );

    let allow: Output = guard_check(&src_file, &["--json"]);
    let allow_out: String = String::from_utf8_lossy(&allow.stdout).into_owned();
    assert!(
        allow.status.success(),
        "json allow must succeed; stdout={allow_out}"
    );
    assert!(
        allow_out.contains("\"decision\": \"allow\"")
            || allow_out.contains("\"decision\":\"allow\""),
        "json allow must contain decision=allow; stdout={allow_out}"
    );

    std::fs::remove_dir_all(&root).ok();
}
