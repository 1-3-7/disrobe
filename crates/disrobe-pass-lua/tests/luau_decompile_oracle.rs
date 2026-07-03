#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::DecompiledChunk;
use disrobe_pass_lua::decompile::decompile_chunk;
use disrobe_pass_lua::reader::common::LuaChunk;
use disrobe_pass_lua::reader::luau;

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

fn find_tool(names: &[&str]) -> Option<String> {
    for name in names {
        let ok: bool = Command::new(name)
            .arg("--help")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty());
        if ok {
            return Some((*name).to_owned());
        }
    }
    None
}

fn run_luau(interp: &str, source: &str) -> Option<String> {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("luau_oracle_{}_{unique}.lua", std::process::id()));
    fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        eprintln!("luau run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

fn recompiles(compiler: &str, source: &str) -> bool {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("luau_recomp_{}_{unique}.lua", std::process::id()));
    if fs::write(&tmp, source).is_err() {
        return false;
    }
    let out = Command::new(compiler).arg("--binary").arg(&tmp).output();
    let _ = fs::remove_file(&tmp);
    out.is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
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

fn recovered_source(name: &str) -> String {
    let bc_path: PathBuf = samples_dir().join(format!("{name}.luau"));
    let bytes: Vec<u8> = fs::read(&bc_path)
        .unwrap_or_else(|e| panic!("luau bytecode fixture {name}.luau must be tracked: {e}"));
    let chunk: LuaChunk = luau::read(&bytes).expect("parse luau bytecode");
    let dc: DecompiledChunk = decompile_chunk(&chunk).expect("luau decompile");
    dc.source
}

fn oracle(name: &str) {
    let Some(interp): Option<String> = find_tool(&["luau", "luau.exe"]) else {
        eprintln!("no luau runtime on PATH; skipping execution oracle for {name}");
        return;
    };
    let src_path: PathBuf = samples_dir().join("src").join(format!("{name}.lua"));
    let original_src: String = fs::read_to_string(&src_path)
        .unwrap_or_else(|e| panic!("source fixture {name}.lua must be tracked: {e}"));
    let expected: String = run_luau(&interp, &original_src)
        .unwrap_or_else(|| panic!("original {name}.lua failed to run under {interp}"));
    let recovered: String = recovered_source(name);
    let actual: String = run_luau(&interp, &recovered)
        .unwrap_or_else(|| panic!("recovered {name} failed to run under {interp}\n{recovered}"));
    assert_eq!(
        normalize(&actual),
        normalize(&expected),
        "{name}: recovered output must match original\n--- recovered ---\n{recovered}"
    );
    eprintln!("luau oracle {name}: OK");
}

#[test]
fn oracle_arith_loops() {
    oracle("arith_loops");
}

#[test]
fn oracle_control_flow() {
    oracle("control_flow");
}

#[test]
fn oracle_oop_functional() {
    oracle("oop_functional");
}

#[test]
fn closures_recursion_recompiles() {
    let Some(compiler): Option<String> = find_tool(&["luau-compile", "luau-compile.exe"]) else {
        eprintln!("no luau-compile on PATH; skipping recompile check");
        return;
    };
    let recovered: String = recovered_source("closures_recursion");
    assert!(
        recompiles(&compiler, &recovered),
        "recovered closures_recursion must recompile via luau-compile\n--- recovered ---\n{recovered}"
    );
}

#[test]
fn all_samples_parse_and_emit_source() {
    for name in [
        "arith_loops",
        "control_flow",
        "closures_recursion",
        "oop_functional",
    ] {
        let recovered: String = recovered_source(name);
        assert!(
            recovered.contains("local function _main"),
            "{name}: expected a _main wrapper in recovered source"
        );
        assert!(
            !recovered.contains("unknown luau op"),
            "{name}: recovered source still contains an unknown-opcode marker"
        );
    }
}
