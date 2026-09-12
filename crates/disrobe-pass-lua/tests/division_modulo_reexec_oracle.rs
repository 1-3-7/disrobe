#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

fn toolchain_51() -> Option<Toolchain> {
    let luac: String = first_existing(&[
        "C:/Program Files (x86)/Lua/5.1/luac.exe".to_owned(),
        "C:/Program Files/Lua/5.1/luac.exe".to_owned(),
        "luac5.1".to_owned(),
    ])?;
    let lua: String = first_existing(&[
        "C:/Program Files (x86)/Lua/5.1/lua.exe".to_owned(),
        "C:/Program Files/Lua/5.1/lua.exe".to_owned(),
        "lua5.1".to_owned(),
    ])?;
    Some(Toolchain { luac, lua })
}

fn toolchain_54() -> Option<Toolchain> {
    let mut luac_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/luac.exe".to_owned(),
        "luac5.4".to_owned(),
    ];
    let mut lua_cands: Vec<String> = vec![
        "C:/Program Files/Lua/5.4/lua.exe".to_owned(),
        "lua5.4".to_owned(),
    ];
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        luac_cands.insert(0, format!("{home}/Programs/Lua/bin/luac.exe"));
        lua_cands.insert(0, format!("{home}/Programs/Lua/bin/lua.exe"));
    }
    let luac: String = first_existing(&luac_cands)?;
    let lua: String = first_existing(&lua_cands)?;
    Some(Toolchain { luac, lua })
}

fn scratch_dir() -> disrobe_core::scratch::ScratchDir {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe_lua_divmod-{}-{seq}", std::process::id());
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

const RUN_TIMEOUT: Duration = Duration::from_secs(8);

fn run_source(lua: &str, dir: &Path, name: &str, source: &str) -> Option<String> {
    let script: PathBuf = dir.join(format!("{name}.run.lua"));
    std::fs::write(&script, source).ok()?;
    let out_path: PathBuf = dir.join(format!("{name}.stdout.txt"));
    let err_path: PathBuf = dir.join(format!("{name}.stderr.txt"));
    let out_file: File = File::create(&out_path).ok()?;
    let err_file: File = File::create(&err_path).ok()?;
    let mut child = Command::new(lua)
        .arg(&script)
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .ok()?;
    let deadline: Instant = Instant::now() + RUN_TIMEOUT;
    let success: bool = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => return None,
        }
    };
    if !success {
        return None;
    }
    let mut combined: String = std::fs::read_to_string(&out_path).ok()?;
    combined.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
    Some(combined.replace("\r\n", "\n"))
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

fn recover_body(tc: &Toolchain, dir: &Path, name: &str, source: &str) -> String {
    let src_path: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&src_path, source).expect("write source");
    let bc_path: PathBuf = dir.join(format!("{name}.luac"));
    assert!(
        compile(&tc.luac, &src_path, &bc_path),
        "luac compiles {name}"
    );
    let bytes: Vec<u8> = std::fs::read(&bc_path).expect("read bytecode");
    let decompiled: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    strip_main_wrapper(&decompiled.source)
}

fn assert_reexec_equivalent(tc: &Toolchain, name: &str, source: &str, must_contain: &[&str]) {
    let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let body: String = recover_body(tc, &dir, name, source);
    for token in must_contain {
        assert!(
            body.contains(token),
            "{name}: recovered source lost the `{token}` operator; a wrong operator changes the \
             division/modulo value.\n--- recovered ---\n{body}"
        );
    }
    let expected: String =
        run_source(&tc.lua, &dir, &format!("{name}.orig"), source).expect("original runs");
    let actual: String =
        run_source(&tc.lua, &dir, &format!("{name}.dec"), &body).expect("recovered runs");
    assert_eq!(
        expected, actual,
        "{name}: recovered division/modulo diverged from the original on negative operands.\n\
         --- expected ---\n{expected}\n--- actual ---\n{actual}\n--- recovered ---\n{body}"
    );
}

const FLOOR_DIV_MOD_54: &str = "local function fq(a, b) return (a // b) end\n\
local function fr(a, b) return (a % b) end\n\
local function fd(a, b) return (a / b) end\n\
local function g(a) return (a // 3), (a % 3), (a // -3), (a % -3) end\n\
print(fq(-7, 3), fq(7, -3), fq(-7, -3), fq(7, 3))\n\
print(fr(-7, 3), fr(7, -3), fr(-7, -3), fr(7, 3))\n\
print(fd(-7, 3), fd(7, -3), fd(-7, -3), fd(7, 3))\n\
print(g(-7))\nprint(g(7))\n";

const FLOOR_DIV_LOOP_54: &str = "local function digits(n)\n\
  local out = \"\"\n\
  while n ~= 0 do\n\
    out = tostring(n % 10) .. out\n\
    n = n // 10\n\
  end\n\
  return out\nend\nprint(digits(12345), digits(1000007))\n";

const FLOAT_MOD_51: &str = "local function fr(a, b) return (a % b) end\n\
local function fd(a, b) return (a / b) end\n\
print(fr(-7, 3), fr(7, -3), fr(-7, -3), fr(7, 3))\n\
print(fd(-7, 3), fd(7, -3), fd(-7, -3), fd(7, 3))\n";

#[test]
fn floor_div_and_modulo_negative_operands_lua_5_4() {
    let Some(tc): Option<Toolchain> = toolchain_54() else {
        eprintln!("skip: lua 5.4 toolchain (luac+lua) not found on box");
        return;
    };
    assert_reexec_equivalent(&tc, "floor_div_mod", FLOOR_DIV_MOD_54, &["//", "%", "/"]);
    assert_reexec_equivalent(&tc, "floor_div_loop", FLOOR_DIV_LOOP_54, &["//", "%"]);
}

#[test]
fn float_modulo_sign_negative_operands_lua_5_1() {
    let Some(tc): Option<Toolchain> = toolchain_51() else {
        eprintln!("skip: lua 5.1 toolchain (luac+lua) not found on box");
        return;
    };
    assert_reexec_equivalent(&tc, "float_mod", FLOAT_MOD_51, &["%", "/"]);
}
