#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::decompile::{DecompiledChunk, decompile_auto};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct Toolchain {
    luac: String,
    lua: String,
}

fn first_existing(candidates: &[String]) -> Option<String> {
    for c in candidates {
        if c.contains('/') || c.contains('\\') {
            if Path::new(c).exists() {
                return Some(c.clone());
            }
        } else if Command::new(c).arg("-v").output().is_ok() {
            return Some(c.clone());
        }
    }
    None
}

fn toolchain_54() -> Option<Toolchain> {
    let mut luac_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/luac.exe".to_owned(),
        "luac5.4".to_owned(),
        "luac".to_owned(),
    ];
    let mut lua_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/lua.exe".to_owned(),
        "lua5.4".to_owned(),
        "lua".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        luac_cands.insert(0, format!("{home}/Programs/Lua/bin/luac.exe"));
        lua_cands.insert(0, format!("{home}/Programs/Lua/bin/lua.exe"));
    }
    let luac: String = first_existing(&luac_cands)?;
    let lua: String = first_existing(&lua_cands)?;
    if !lua_reports_54(&lua) {
        return None;
    }
    Some(Toolchain { luac, lua })
}

fn lua_reports_54(lua: &str) -> bool {
    Command::new(lua).arg("-v").output().is_ok_and(|o| {
        let banner: String = String::from_utf8_lossy(&o.stdout).into_owned();
        banner.contains("Lua 5.4")
    })
}

fn scratch_dir() -> disrobe_core::scratch::ScratchDir {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_boolchain-{}-{seq}", std::process::id());
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn compile(luac: &str, src: &Path, out: &Path) -> bool {
    Command::new(luac)
        .arg("-o")
        .arg(out)
        .arg(src)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success())
}

fn run_source(lua: &str, dir: &Path, name: &str, source: &str) -> Option<String> {
    let script: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&script, source).ok()?;
    let out: std::process::Output = Command::new(lua).arg(&script).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let mut s: String = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s.replace("\r\n", "\n"))
}

fn strip_main_wrapper(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start: usize = lines
        .iter()
        .position(|l: &&str| l.trim_start().starts_with("function _main"))
        .map_or(0, |i: usize| i + 1);
    let end: usize = lines
        .iter()
        .rposition(|l: &&str| l.trim() == "end")
        .unwrap_or(lines.len());
    if start >= end {
        return source.to_owned();
    }
    lines[start..end].join("\n")
}

const CASES: &[(&str, &str)] = &[
    (
        "or_two_comparisons",
        "local function f(a, b) return a < 0 or b < 0 end\nprint(f(-1, 2), f(1, -2), f(1, 2), f(-3, -4))\n",
    ),
    (
        "and_two_comparisons",
        "local function f(a, b) return a > 0 and b > 0 end\nprint(f(1, 1), f(1, -1), f(-1, 1), f(-2, -2))\n",
    ),
    (
        "or_three_comparisons",
        "local function f(a, b, c) return a < 0 or b < 0 or c < 0 end\nprint(f(1, 2, 3), f(-1, 2, 3), f(1, -2, 3), f(1, 2, -3), f(1, 2, 3))\n",
    ),
    (
        "and_three_comparisons",
        "local function f(a, b, c) return a < 0 and b < 0 and c < 0 end\nprint(f(-1, -2, -3), f(-1, -2, 3), f(1, -2, -3), f(1, 2, 3))\n",
    ),
    (
        "mixed_or_of_and",
        "local function f(a, b, c) return a < 0 or b < 0 and c < 0 end\nprint(f(-1, 5, 5), f(5, -1, -1), f(5, -1, 5), f(5, 5, 5))\n",
    ),
    (
        "between_ge_and_le",
        "local function f(x, lo, hi) return x >= lo and x <= hi end\nprint(f(5, 1, 10), f(0, 1, 10), f(10, 1, 10), f(11, 1, 10))\n",
    ),
    (
        "eq_immediate_or_chain",
        "local function f(a, b) return a == 1 or b == 2 end\nprint(f(1, 9), f(9, 2), f(9, 9), f(1, 2))\n",
    ),
];

#[test]
fn boolean_and_or_chain_survives_recompile_and_reexec_lua_5_4() {
    let Some(tc): Option<Toolchain> = toolchain_54() else {
        eprintln!("skip: lua 5.4 toolchain (luac+lua) not found on box");
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut failures: Vec<String> = Vec::new();
    for (name, source) in CASES {
        let src_path: PathBuf = dir.join(format!("{name}.src.lua"));
        std::fs::write(&src_path, source).expect("write source");
        let bc_path: PathBuf = dir.join(format!("{name}.luac"));
        if !compile(&tc.luac, &src_path, &bc_path) {
            failures.push(format!("{name}: luac failed to compile fixture"));
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&bc_path).expect("read bytecode");
        let decompiled: DecompiledChunk = match decompile_auto(&bytes) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{name}: decompile error {e:?}"));
                continue;
            }
        };
        let body: String = strip_main_wrapper(&decompiled.source);
        let expected: Option<String> = run_source(&tc.lua, &dir, &format!("{name}.orig"), source);
        let actual: Option<String> = run_source(&tc.lua, &dir, &format!("{name}.dec"), &body);
        match (expected, actual) {
            (Some(e), Some(a)) if e == a => {}
            (Some(e), Some(a)) => failures.push(format!(
                "{name}: recovered source re-executes to a different value\n  expected={e:?}\n  actual={a:?}\n  recovered=\n{body}"
            )),
            (Some(_), None) => failures.push(format!(
                "{name}: recovered source failed to run (syntax or runtime error)\n  recovered=\n{body}"
            )),
            (None, _) => failures.push(format!("{name}: original fixture failed to run")),
        }
    }
    assert!(
        failures.is_empty(),
        "boolean and/or chain regression: {} case(s) diverged after recompile-and-reexec\n{}",
        failures.len(),
        failures.join("\n----\n")
    );
}
