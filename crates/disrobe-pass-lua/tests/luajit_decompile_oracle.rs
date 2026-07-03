#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::decompile::{self, DecompiledChunk};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn samples_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    p.push("decompile_samples");
    p
}

fn find_luajit() -> Option<String> {
    for name in ["luajit", "luajit-2.1", "luajit.exe"] {
        let ok: bool = Command::new(name)
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty());
        if ok {
            return Some(name.to_owned());
        }
    }
    None
}

fn run_luajit(interp: &str, source: &str) -> Option<String> {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("lj_oracle_{}_{unique}.lua", std::process::id()));
    fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        eprintln!(
            "luajit run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

fn normalize(s: &str) -> String {
    let mut out: String = String::new();
    for line in s.lines() {
        out.push_str(&strip_src_locations(line));
        out.push('\n');
    }
    out.trim_end().to_owned()
}

fn strip_src_locations(line: &str) -> String {
    let mut result: String = String::new();
    let bytes: &[u8] = line.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            let mut j: usize = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b':' {
                let start: usize = result
                    .rfind(char::is_whitespace)
                    .map_or(0, |p: usize| p + 1);
                result.truncate(start);
                result.push_str("SRC:");
                i = j + 1;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn oracle(name: &str, variant: &str) {
    let Some(interp): Option<String> = find_luajit() else {
        eprintln!("no luajit on PATH; skipping execution oracle for {name}.{variant}");
        return;
    };
    let dir: PathBuf = samples_dir();
    let src_path: PathBuf = dir.join("src").join(format!("{name}.lua"));
    let bc_path: PathBuf = dir.join(format!("{name}{variant}.luajit"));
    let original_src: String = fs::read_to_string(&src_path)
        .unwrap_or_else(|e| panic!("source fixture {name}.lua must be tracked: {e}"));
    let bytes: Vec<u8> = fs::read(&bc_path)
        .unwrap_or_else(|e| panic!("bytecode fixture {name}{variant}.luajit must be tracked: {e}"));

    let expected: String = run_luajit(&interp, &original_src)
        .unwrap_or_else(|| panic!("original {name}.lua failed to run under {interp}"));

    let recovered: DecompiledChunk =
        decompile::luajit_lift::decompile(&bytes).expect("luajit decompile");
    let actual: String = run_luajit(&interp, &recovered.source).unwrap_or_else(|| {
        panic!(
            "recovered {name}{variant} failed to run under {interp}\n--- recovered ---\n{}",
            recovered.source
        )
    });

    assert_eq!(
        normalize(&actual),
        normalize(&expected),
        "{name}{variant}: recovered output must match original\n--- recovered source ---\n{}",
        recovered.source
    );
    eprintln!("luajit oracle {name}{variant}: OK");
}

#[test]
fn oracle_arith_loops() {
    oracle("arith_loops", "");
}

#[test]
fn oracle_arith_loops_stripped() {
    oracle("arith_loops", ".stripped");
}

#[test]
fn oracle_control_flow() {
    oracle("control_flow", "");
}

#[test]
fn oracle_control_flow_stripped() {
    oracle("control_flow", ".stripped");
}

#[test]
fn oracle_closures_recursion() {
    oracle("closures_recursion", "");
}

#[test]
fn oracle_closures_recursion_stripped() {
    oracle("closures_recursion", ".stripped");
}

#[test]
fn oracle_oop_functional() {
    oracle("oop_functional", "");
}

#[test]
fn oracle_oop_functional_stripped() {
    oracle("oop_functional", ".stripped");
}

#[test]
fn oracle_luajit_20_version_byte() {
    oracle("arith_loops", ".lj20");
}

#[test]
fn megafile_recovers_and_runs_under_luajit() {
    let Some(interp): Option<String> = find_luajit() else {
        eprintln!("no luajit on PATH; skipping megafile oracle");
        return;
    };
    let mut mega: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    mega.pop();
    mega.pop();
    mega.push("corpus");
    mega.push("lua");
    let src: PathBuf = mega.join("megafile").join("edge_cases.lua");
    let bc: PathBuf = mega.join("luajit").join("edge_cases.luajit");
    let original_src: String = fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", src.display()));
    let bytes: Vec<u8> =
        fs::read(&bc).unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", bc.display()));
    let expected: String =
        run_luajit(&interp, &original_src).expect("megafile original must run under luajit");
    let recovered: DecompiledChunk =
        decompile::luajit_lift::decompile(&bytes).expect("megafile decompile");
    let actual: String = run_luajit(&interp, &recovered.source).unwrap_or_else(|| {
        panic!(
            "recovered megafile failed to run under {interp}\n--- first 2000 chars ---\n{}",
            &recovered.source.chars().take(2000).collect::<String>()
        )
    });
    assert_eq!(
        normalize(&actual),
        normalize(&expected),
        "megafile recovered output must match original"
    );
}
