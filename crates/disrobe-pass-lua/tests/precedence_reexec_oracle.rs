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

fn scratch_dir() -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_lua_prec-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
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
        "unary_minus_is_exponent_base",
        "local function f(a, b) return (-a) ^ b end\nprint(f(2, 2), f(3, 2), f(2, 3))\n",
    ),
    (
        "bitwise_not_is_exponent_base",
        "local function f(a, b) return (~a) ^ b end\nprint(f(5, 2), f(1, 3))\n",
    ),
    (
        "length_is_exponent_base",
        "local function f(t) return (#t) ^ 2 end\nprint(f({1, 2, 3}), f({1, 2, 3, 4, 5}))\n",
    ),
    (
        "unary_minus_on_binary",
        "local function f(a, b) return -(a - b) end\nprint(f(3, 10), f(10, 3))\n",
    ),
    (
        "double_unary_minus",
        "local function f(a) return -(-a) end\nprint(f(7), f(-4))\n",
    ),
    (
        "subtraction_right_operand",
        "local function f(a, b, c) return a - (b - c) end\nprint(f(20, 8, 3))\n",
    ),
    (
        "division_right_operand",
        "local function f(a, b, c) return a / (b / c) end\nprint(f(64, 8, 2))\n",
    ),
    (
        "exponent_right_associative",
        "local function f(a, b, c) return a ^ (b ^ c) end\nprint(f(2, 3, 2))\n",
    ),
    (
        "exponent_left_forced",
        "local function f(a, b, c) return (a ^ b) ^ c end\nprint(f(2, 3, 2))\n",
    ),
    (
        "concat_right_associative",
        "local function f(a, b, c) return a .. (b .. c) end\nprint(f('x', 'y', 'z'))\n",
    ),
    (
        "shift_over_additive",
        "local function f(a, b, c) return a << (b + c) end\nprint(f(1, 2, 3))\n",
    ),
    (
        "bitwise_and_over_additive",
        "local function f(a, b, c) return (a + b) & c end\nprint(f(6, 1, 3))\n",
    ),
    (
        "not_binds_over_and_or",
        "local function f(a, b, c) return not a and b or c end\nprint(f(false, 'x', 'y'), f(true, 'x', 'y'))\n",
    ),
    (
        "modulo_right_operand",
        "local function f(a, b, c) return a % (b % c) end\nprint(f(17, 12, 5))\n",
    ),
    (
        "floor_div_right_operand",
        "local function f(a, b, c) return a // (b // c) end\nprint(f(100, 20, 3))\n",
    ),
];

#[test]
fn precedence_survives_recompile_and_reexec_lua_5_4() {
    let Some(tc): Option<Toolchain> = toolchain_54() else {
        eprintln!("skip: lua 5.4 toolchain (luac+lua) not found on box");
        return;
    };
    let dir: PathBuf = scratch_dir();
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
        "precedence regression: {} case(s) diverged after recompile-and-reexec\n{}",
        failures.len(),
        failures.join("\n----\n")
    );
}
