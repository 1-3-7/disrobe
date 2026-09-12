#![cfg(all(feature = "chain", feature = "shell"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn unique_tmp(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-cli-final-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn read_output_bin(dir: &Path) -> Vec<u8> {
    let bin: PathBuf = dir.join("output.bin");
    std::fs::read(&bin)
        .unwrap_or_else(|e| panic!("output.bin unreadable at {}: {e}", bin.display()))
}

#[test]
fn out_final_resolves_to_terminal_output_regardless_of_mechanism() {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli` first",
        bin.display()
    );

    let root_scratch: disrobe_core::scratch::ScratchDir = unique_tmp("root");

    let root: PathBuf = root_scratch.path().to_path_buf();
    let out_dir: PathBuf = root.join("out");
    let input: PathBuf = root.join("script.sh");
    std::fs::create_dir_all(&root).expect("mk root");
    std::fs::write(
        &input,
        b"#!/bin/bash\neval \"$(echo ZWNobyBoaQ== | base64 -d)\"\necho done\n",
    )
    .expect("write input");

    let output: std::process::Output = std::process::Command::new(&bin)
        .args([
            "chain",
            input.display().to_string().as_str(),
            "--out",
            out_dir.display().to_string().as_str(),
            "--chain",
            "shell.deob",
            "--capture-stages",
        ])
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    assert!(
        output.status.success(),
        "chain exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let final_dir: PathBuf = out_dir.join("final");
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(&final_dir)
        .unwrap_or_else(|e| panic!("read final/ at {}: {e}", final_dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p: &PathBuf| p.is_dir())
        .collect();
    subdirs.sort();
    assert_eq!(
        subdirs.len(),
        1,
        "linear chain must produce exactly one terminal, got {subdirs:?}"
    );

    let terminal_subdir: &PathBuf = &subdirs[0];
    let final_bytes: Vec<u8> = read_output_bin(terminal_subdir);

    let slug: &std::ffi::OsStr = terminal_subdir.file_name().expect("named terminal subdir");
    let mirror_stage: PathBuf = out_dir.join(slug);
    let stage_bytes: Vec<u8> = read_output_bin(&mirror_stage);

    assert_eq!(
        final_bytes,
        stage_bytes,
        "final/{} must resolve to the terminal stage bytes",
        slug.to_string_lossy()
    );
    assert!(
        !final_bytes.is_empty(),
        "terminal output must be non-empty for this fixture"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn out_final_resolves_with_relative_out_and_cwd() {
    let bin: PathBuf = cli_binary();
    let root_scratch: disrobe_core::scratch::ScratchDir = unique_tmp("relout");
    let root: PathBuf = root_scratch.path().to_path_buf();
    std::fs::create_dir_all(&root).expect("mk root");
    let input: PathBuf = root.join("script.sh");
    std::fs::write(
        &input,
        b"#!/bin/bash\neval \"$(echo ZWNobyBoaQ== | base64 -d)\"\necho done\n",
    )
    .expect("write input");

    let output: std::process::Output = std::process::Command::new(&bin)
        .current_dir(&root)
        .args([
            "chain",
            "script.sh",
            "--out",
            "out",
            "--chain",
            "shell.deob",
            "--capture-stages",
        ])
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    assert!(
        output.status.success(),
        "chain exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let final_dir: PathBuf = root.join("out").join("final");
    let terminal: PathBuf = std::fs::read_dir(&final_dir)
        .unwrap_or_else(|e| panic!("read final/ at {}: {e}", final_dir.display()))
        .map(|e| e.expect("dir entry").path())
        .find(|p: &PathBuf| p.is_dir())
        .expect("one terminal final subdir");
    let final_bytes: Vec<u8> = read_output_bin(&terminal);
    assert!(
        !final_bytes.is_empty(),
        "relative --out: out/final must resolve to non-empty terminal bytes (regression: relative symlink target was dangling)"
    );

    let _ = std::fs::remove_dir_all(&root);
}
