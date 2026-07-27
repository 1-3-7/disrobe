#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::ptr_arg,
    dead_code,
    unreachable_pub
)]

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn cli_binary() -> PathBuf {
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

pub fn temp_path(stem: &str, ext: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-cli-flags-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let basename: &std::ffi::OsStr = scratch
        .path()
        .file_name()
        .expect("scratch directory has a basename");
    let filename: String = format!("{}.{ext}", basename.to_string_lossy());
    let path: PathBuf = scratch.path().join(filename);
    (scratch, path)
}

pub fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-cli-flags-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

pub fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _: std::io::Result<()> = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, bytes).expect("write fixture");
}

#[derive(Debug)]
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_disrobe(args: &[&str]) -> Run {
    run_disrobe_env(args, &[])
}

pub fn run_disrobe_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    let mut cmd: Command = Command::new(&bin);
    cmd.args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output: std::process::Output = cmd.output().expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

pub fn minimal_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}
