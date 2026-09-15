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
    let purpose: String = format!("disrobe-stage-mirror-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn numbered_step_dirs(out_dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .unwrap_or_else(|e| panic!("read out/ at {}: {e}", out_dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p: &PathBuf| {
            p.is_dir()
                && p.file_name()
                    .and_then(|s: &std::ffi::OsStr| s.to_str())
                    .is_some_and(|n: &str| {
                        let b: &[u8] = n.as_bytes();
                        b.len() >= 3
                            && b[0].is_ascii_digit()
                            && b[1].is_ascii_digit()
                            && b[2] == b'-'
                    })
        })
        .collect();
    dirs.sort();
    dirs
}

#[test]
fn capture_stages_writes_flat_numbered_step_dirs_with_real_content() {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli --features chain,shell` first",
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

    assert!(out_dir.join("chain.json").is_file(), "chain.json missing");
    assert!(
        out_dir.join("recovery.json").is_file(),
        "recovery.json missing"
    );
    assert!(
        !out_dir.join("stages").exists(),
        "legacy stages/ wrapper must NOT be created under the flat layout"
    );

    let steps: Vec<PathBuf> = numbered_step_dirs(&out_dir);
    assert!(
        !steps.is_empty(),
        "expected >=1 flat NN-<pass>/ step dir under {}",
        out_dir.display()
    );
    let first_name: String = steps[0]
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .expect("step name")
        .to_string();
    assert!(
        first_name.starts_with("01-"),
        "numbering must be 1-based; first step was {first_name}"
    );
    for step in &steps {
        let bin_path: PathBuf = step.join("output.bin");
        let bytes: Vec<u8> = std::fs::read(&bin_path)
            .unwrap_or_else(|e| panic!("output.bin unreadable at {}: {e}", bin_path.display()));
        assert!(
            !bytes.is_empty(),
            "step {} output.bin empty",
            step.display()
        );
    }

    let final_dir: PathBuf = out_dir.join("final");
    let mut terminals: Vec<PathBuf> = std::fs::read_dir(&final_dir)
        .unwrap_or_else(|e| panic!("read final/ at {}: {e}", final_dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p: &PathBuf| p.is_dir())
        .collect();
    terminals.sort();
    assert_eq!(
        terminals.len(),
        1,
        "linear shell.deob chain must yield exactly one terminal, got {terminals:?}"
    );
    let terminal: &PathBuf = &terminals[0];
    let terminal_name: &std::ffi::OsStr = terminal.file_name().expect("named terminal");
    let final_bytes: Vec<u8> =
        std::fs::read(terminal.join("output.bin")).expect("final output.bin readable");
    let mirror_bytes: Vec<u8> = std::fs::read(out_dir.join(terminal_name).join("output.bin"))
        .expect("flat step output.bin readable");
    assert_eq!(
        final_bytes,
        mirror_bytes,
        "final/{} must resolve to the flat step's terminal bytes",
        terminal_name.to_string_lossy()
    );
    assert!(!final_bytes.is_empty(), "terminal output must be non-empty");

    let _ = std::fs::remove_dir_all(&root);
}
